## 0.1.17 – Säker CRM-flytt och GitHub-synk

- Återställer CRM-SSO-migrationen efter att lokal GitHub-synk skrev tillbaka en äldre version.
- Lokal GitHub-synk förhindras från att skriva över en lika ny eller nyare kodversion på GitHub.
- För att få nya funktioner måste ny release installeras under Admin → System; Synka aktuell version laddar upp lokal kod till GitHub och uppdaterar inte Hello.

## 0.1.16 – CRM-domän för Hello SSO

- **Admin → System → Hopefli SSO**: ändra issuer till `https://crm.hopefli.se` utan att skriva in klienthemligheten igen. Issuer verifieras mot OIDC-discovery innan lagring. Befintligt klient-ID och redirect URI behålls.
- När CRM-issuer sparas flyttas även sparad personal-API-basadress och uppdrags-API till CRM. Interna `CMS_*`-miljövariabler/nycklar behålls för bakåtkompatibilitet.
- Hellos synliga texter och systemlänken ändras från CMS till CRM. Den tidigare SSO-inställningen förblir aktiv fram till admin själv sparar den nya.
- Testa ny SSO-inloggning i ett privat fönster innan `cms.hopefli.se` avvecklas.

# Hopefli Hello v0.1.15

- BookStack standardlänk ändrad till https://bookstack.hopefli.se
- Uppdrag borttaget från huvudmenyn.
- Dashboard-widgeten för kommande uppdrag och länken Visa alla finns kvar.

# Hopefli Hello v0.1.12

- Tar bort Hopefli Play-kortet från startsidans snabbval.
- Lägger till personal-API-diagnostik under Admin → System.
- Diagnostiken visar antal mottagna/visade/filtrerade CMS-poster och säker orsak per person.
- Avsaknad profilbild filtrerar inte bort en person; diagnostiken markerar att avatar används.
- Ingen CMS access token eller rått API-svar visas i adminvyn.

## v0.1.13 – Personalhandbok snabbimport

- Admin → Personalhandbok har nu **Lägg in Hopefli-standard**.
- 8 kategorier och 24 korta Hopefli-anpassade artiklar följer med.
- Standardimporten är icke-destruktiv: egna artiklar raderas inte.
- Import av handbok från JSON-fil.
- Export av aktuell handbok till JSON.


## 0.1.15
- Dashboardens systemkort 02 heter nu **Spela**.
- Kortet länkar till `https://spela.hopefli.se`.
- Beskrivning: “Quiz, musik och aktiviteter.”
