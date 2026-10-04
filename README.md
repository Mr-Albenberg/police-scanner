# Police Scanner

Live San Luis Obispo County sheriff, police and fire radio with a running transcript and a dispatch map.

**Open it:** https://mr-albenberg.github.io/police-scanner/

- Plays the county scanner feed and transcribes each call as you hear it (Groq · Whisper Large v3)
- Pins each call on the map and draws the street when only a street is named
- Colors calls by who handles them (blue medical, red fire, orange police; split when more than one; green when resolved)
- Explains radio codes (10-codes, 11-codes, penal and vehicle code numbers) and decodes Morse code IDs
- Alerts you when a call is near your location or on a street you watch

## Key relay

Transcription uses a shared Groq key that never reaches the browser. It lives in a small Cloudflare Worker (`relay/worker.js`) that only accepts requests from this site, only for transcription and the address check, and only for the models the site uses. Anyone can also paste their own free Groq key in Settings; it is stored only in their browser and sent straight to Groq.

To set up the relay: create a Worker in Cloudflare, paste `relay/worker.js`, add a secret named `GROQ_KEY`, and put the Worker's address in `RELAY_URL` in `index.html`.
