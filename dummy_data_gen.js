const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('vulnerabilities.db');

const projectTypes = ['web', 'api', 'mobile', 'infra', 'phishing'];
const clientPrefixes = ['Bank', 'PT', 'Kementerian', 'Dinas', 'Startup', 'E-Commerce', 'Fintech'];

function getRandomDate(start, end) {
  return new Date(start.getTime() + Math.random() * (end.getTime() - start.getTime()));
}

function generateDummyData() {
  const cy = new Date().getFullYear();
  const today = new Date();
  
  // We'll generate 25 dummy projects across the last 12 months.
  for(let i=0; i<25; i++) {
     const pType = projectTypes[Math.floor(Math.random()*projectTypes.length)];
     const cName = clientPrefixes[Math.floor(Math.random()*clientPrefixes.length)] + ' ' + Math.random().toString(36).substring(7).toUpperCase();
     
     // Random kick off date from (today - 12 months) to today
     const startRange = new Date(today.getFullYear() - 1, today.getMonth(), today.getDate());
     const kickOff = getRandomDate(startRange, today);
     const kickoffStr = kickOff.toLocaleDateString('en-CA');
     
     // Insert into clients first
     db.run('INSERT INTO clients (name) VALUES (?)', [cName], function(err) {
        if(err) return console.error(err);
        const clientId = this.lastID;
        
        // Project variables
        const isClosed = Math.random() > 0.4; // 60% chance it's completed
        const initialDone = isClosed || Math.random() > 0.5;
        
        // Base mandays between 3 to 15
        const mandays = Math.floor(Math.random() * 12) + 3;
        
        // Report Dates
        let finalReportDate = new Date(kickOff);
        finalReportDate.setDate(finalReportDate.getDate() + mandays + 63); // ~60 days rem + 2 retest + 1 final
        const finalReportDateStr = finalReportDate.toLocaleDateString('en-CA');
        
        let initialReportDate = new Date(kickOff);
        initialReportDate.setDate(initialReportDate.getDate() + mandays + 5);
        const initialReportDateStr = initialReportDate.toLocaleDateString('en-CA');
        
        const boardStatus = isClosed ? -1 : (Math.floor(Math.random()*3) + 1); // -1 is Closed, others 1,2,3
        
        let completedAt = null;
        if (isClosed) {
           let compl = new Date(kickOff);
           // Completed somewhere between kickoff + 30 and kickoff + 90
           compl.setDate(compl.getDate() + 30 + Math.floor(Math.random()*60));
           completedAt = compl.toLocaleDateString('en-CA');
        }
        
        const query = `
          INSERT INTO projects (
            client_id, name, project_type, kickoff_date,
            initial_report_date, initial_report_status,
            final_report_date, final_report_status, final_completed_at,
            board_status_id,
            mandays_assessment, assigned_engineer_id
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        
        db.run(query, [
          clientId, 'Assessment for ' + cName, pType, kickoffStr,
          initialReportDateStr, initialDone ? 'completed' : 'pending',
          finalReportDateStr, isClosed ? 'completed' : 'pending', completedAt,
          boardStatus,
          mandays, 1 // Assuming 1 is a valid engineer
        ], function(err2) {
           if(err2) console.error(err2);
           else console.log('Inserted dummy project ID:', this.lastID);
        });
     });
  }
}

generateDummyData();
