# Mail Security Score

En statisk, norsk webapp som gir et domene en e-postsikkerhetsscore fra 0 til 100.

## Kontroller

- DNSSEC
- SPF
- DKIM
- DMARC
- MTA-STS
- TLS-RPT
- DANE/TLSA for SMTP på port 25
- CAA
- BIMI
- MX-redundans
- IPv6 på MX-servere
- DNS-konfigurasjon
- HTTPS/TLS-sertifikatstatus via nettleserens validering

Appen viser også de tre forbedringene som kan gi størst poengmessig gevinst.

## Datakilder og begrensninger

DNS-oppslag gjøres direkte fra nettleseren mot Cloudflare DNS-over-HTTPS (`application/dns-json`).

DKIM-selectorer er ikke standardiserte. En manglende nøkkel blant vanlige selectorer betyr derfor ikke nødvendigvis at domenet mangler DKIM. Brukeren kan oppgi korrekt selector manuelt.

DANE/TLSA kontrolleres på `_25._tcp.<mx-host>` og vurderes sammen med DNSSEC-validering.

Sertifikatkontrollen bruker en `no-cors` HTTPS-forespørsel for å se om nettleseren klarer en betrodd TLS-tilkobling til rotdomenet. En ren statisk side kan ikke lese sertifikatets utløpsdato eller inspisere SMTP STARTTLS-sertifikatet direkte. For full SMTP-sertifikatanalyse anbefales en liten backend eller en dedikert TLS-API.
