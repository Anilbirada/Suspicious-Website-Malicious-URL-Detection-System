import React from 'react';
import { RiskCategory } from '../types/api';

interface RiskBadgeProps {
  category: RiskCategory;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ category }) => {
  let variantClass = 'neutral';
  if (category === 'Potentially Malicious') {
    variantClass = 'high';
  } else if (category === 'Suspicious') {
    variantClass = 'medium';
  } else if (category === 'Lower Risk Indicators Found') {
    variantClass = 'low';
  }

  return (
    <span className={`risk-badge ${variantClass}`} data-testid="risk-category-badge">
      {category}
    </span>
  );
};
