<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>GoBiz Proxy Docs</title>
  <link rel="stylesheet" href="/public/app.css"/>
</head>
<body>
  <div class="home">
    <div class="homeCard">
      <div class="homeTop">
        <div class="homeLogo">G</div>
        <div>
          <div class="homeTitle">GoBiz Proxy Docs</div>
          <div class="homeSub">API Explorer UI (Live)</div>
        </div>
      </div>

      <div class="homeMeta">
        <div class="homeMetaK">Upstream</div>
        <div class="homeMetaV mono"><%= baseUrl %></div>
      </div>

      <a class="btn primary" href="/docs">Open API Explorer</a>

      <div class="muted small" style="margin-top:10px">
        Flow: Request OTP → auto simpan otp_token → Verify cukup input OTP.
      </div>
    </div>
  </div>
</body>
</html>
