const { google } = require('googleapis');
const fs = require('fs');

async function run() {
  const msgId = process.argv[2];
  if (!msgId) {
    console.error('Missing message ID');
    process.exit(1);
  }

  const clientId = process.env.GMAIL_CLIENT_ID;
  const clientSecret = process.env.GMAIL_CLIENT_SECRET;
  const refreshToken = process.env.GMAIL_REFRESH_TOKEN;

  if (!clientId || !clientSecret || !refreshToken) {
    console.error("Missing required environment variables: GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, or GMAIL_REFRESH_TOKEN");
    process.exit(1);
  }

  const oauth2Client = new google.auth.OAuth2(
    clientId,
    clientSecret,
    'https://developers.google.com/oauthplayground'
  );

  oauth2Client.setCredentials({ refresh_token: refreshToken });

  const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

  try {
    const res = await gmail.users.messages.get({
      userId: 'mailinglist@sysaifoundation.org',
      id: msgId,
      format: 'raw'
    });

    if (!res.data.raw) {
      throw new Error('No raw content found');
    }

    // Decode base64url
    const raw = res.data.raw;
    const buffer = Buffer.from(raw, 'base64url');
    
    process.stdout.write(buffer);
  } catch (error) {
    console.error('Error fetching patch:', error);
    process.exit(1);
  }
}

run();
