const http = require('http');

async function login(port, username, password) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({ username, password });
    const req = http.request({
      hostname: 'localhost',
      port: port,
      path: '/api/login',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        const setCookie = res.headers['set-cookie'];
        let cookie = '';
        if (setCookie && setCookie.length > 0) {
          cookie = setCookie[0].split(';')[0];
        }
        let body = {};
        try {
          body = JSON.parse(data);
        } catch (e) {
          body = data;
        }
        resolve({
          statusCode: res.statusCode,
          cookie,
          body
        });
      });
    });

    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}

module.exports = { login };
