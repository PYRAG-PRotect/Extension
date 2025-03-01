   // test.js
   import analyzeSecurityIssues from './gem.js';

   async function testAnalyzeSecurityIssues() {
     try {
       const ip = '127.0.0.1'; // Example input, replace with actual test data
       const result = await analyzeSecurityIssues(ip);
       console.log('Test Result:', result);
     } catch (error) {
       console.error('Error during test:', error);
     }
   }

   testAnalyzeSecurityIssues();