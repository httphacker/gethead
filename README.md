# HTTP-CHECK

HTTP-CHECK is a HTTP headers analysis tool forked from httphacker/gethead.

### FEATURES
This script checks these headers:
* Access-Control-Allow-Origin
* Cache-control
* Strict-Transport-Security
* Content-Security-Policy
* X-XSS-Protection
* X-Frame-Options
* X-Content-Type-Options
* X-Download-Options
* X-Permitted-Cross-Domain-Policies
* X-Content-Security-Policy [DEPRECATED]
* X-Webkit-CSP [DEPRECATED]

### INSTALLATION

```sh
git clone https://github.com/phra/http-check.git
```

### EXECUTION
```sh
python http-check.py <URL>
```