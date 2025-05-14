package licensing

import (
	"slices"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing/expression"
)

type ScannerOption struct {
	IgnoredLicenses   []string
	LicenseCategories map[types.LicenseCategory][]string
}

type Scanner struct {
	categories map[types.LicenseCategory][]string
}

func NewScanner(categories map[types.LicenseCategory][]string) Scanner {
	return Scanner{categories: categories}
}

func (s *Scanner) Scan(licenseName string) (types.LicenseCategory, string) {
	category := types.CategoryUnknown
	compoundFound := false

	detectCategoryAndSeverity := func(expr expression.Expression) expression.Expression {
		switch e := expr.(type) {
		case expression.SimpleExpr:
			if !compoundFound {
				category = s.licenseToCategory(e)
			}
		case expression.CompoundExpr:
			category = s.compoundLicenseToCategory(e)
			compoundFound = true
		}

		return expr
	}

	_, err := expression.Normalize(licenseName, NormalizeLicense, detectCategoryAndSeverity)
	if err != nil {
		return types.CategoryUnknown, dbTypes.SeverityUnknown.String()
	}

	return category, categoryToSeverity(category).String()
}

func (s *Scanner) licenseToCategory(license expression.SimpleExpr) types.LicenseCategory {
	for category, names := range s.categories {
		if slices.Contains(names, license.License) {
			return category
		}
	}
	return types.CategoryUnknown
}

func categoryToSeverity(category types.LicenseCategory) dbTypes.Severity {
	switch category {
	case types.CategoryForbidden:
		return dbTypes.SeverityCritical
	case types.CategoryRestricted:
		return dbTypes.SeverityHigh
	case types.CategoryReciprocal:
		return dbTypes.SeverityMedium
	case types.CategoryNotice, types.CategoryPermissive, types.CategoryUnencumbered:
		return dbTypes.SeverityLow
	}
	return dbTypes.SeverityUnknown
}

func (s *Scanner) compoundLicenseToCategory(license expression.CompoundExpr) types.LicenseCategory {
	switch license.Conjunction() {
	case expression.TokenAnd:
		return s.compoundLogicOperator(license, true)
	case expression.TokenOR:
		return s.compoundLogicOperator(license, false)
	default:
		return types.CategoryUnknown
	}
}

func (s *Scanner) compoundLogicOperator(license expression.CompoundExpr, findMax bool) types.LicenseCategory {
	lCategory, lSeverity := s.Scan(license.Left().String())
	rCategory, rSeverity := s.Scan(license.Right().String())

	if lSeverity == dbTypes.SeverityUnknown.String() || rSeverity == dbTypes.SeverityUnknown.String() {
		return types.CategoryUnknown
	}

	var logicOperator int
	if findMax {
		logicOperator = 1
	} else {
		logicOperator = -1
	}

	var compoundCategory types.LicenseCategory
	if 0 < logicOperator*dbTypes.CompareSeverityString(lSeverity, rSeverity) {
		compoundCategory = rCategory
	} else {
		compoundCategory = lCategory
	}

	return compoundCategory
}
