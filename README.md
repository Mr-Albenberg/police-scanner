# Police Scanner

Live San Luis Obispo County sheriff, police and fire radio with a running transcript and a dispatch map.

**Open it:** https://mr-albenberg.github.io/police-scanner/

- Plays the county scanner feed and transcribes each call as you hear it (Groq · Whisper Large v3)
- Pins each call on the map and draws the street when only a street is named
- Colors calls by who handles them (blue medical, red fire, orange police; split when more than one; green when resolved)
- Explains radio codes (10-codes, 11-codes, penal and vehicle code numbers) and decodes Morse code IDs
- Alerts you when a call is near your location or on a street you watch

## Groq key

The site has a default Groq key built in, so it works for everyone with no setup. Anyone can paste their own free Groq key in Settings instead; it is stored only in their browser and sent straight to Groq.

Optional: to keep the default key off the page entirely, deploy `relay/worker.js` as a Cloudflare Worker with a secret named `GROQ_KEY`, set `RELAY_URL` in `index.html` to the Worker's address, and remove `SHARED_GROQ`.
