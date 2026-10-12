import React from 'react';

export const Footer: React.FC = () => {
  return (
    <footer className="app-footer" role="contentinfo">
      <div className="footer-inner">
        <div>
          Suspicious Website / Malicious URL Detection System &mdash; Lexical URL Risk Assessment
        </div>
        <div className="footer-credit" data-testid="developer-footer-credit">
          Developed by Anil Biradar
        </div>
      </div>
    </footer>
  );
};
