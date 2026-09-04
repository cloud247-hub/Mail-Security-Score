const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';
const TYPES = { A:1, NS:2, CNAME:5, SOA:6, MX:15, TXT:16, AAAA:28, DS:43, RRSIG:46, DNSKEY:48, TLSA:52, CAA:257 };
const WEIGHTS = { dnssec:10, spf:12, dkim:12, dmarc:15, mtasts:8, tlsrpt:6, dane:8, caa:5, bimi:2, mxredundancy:6, ipv6mail:4, dnsconfig:6, certificate:6 };
const commonSelectors = [
  'selector1','selector2','google','default','dkim','mail','smtp','email',
  's1','s2','k1','k2','k3','key1','key2','dkim1','dkim2','m1','m2',
  'mandrill','mailjet','smtpapi','protonmail','protonmail2','protonmail3',
  'zoho','zmail','dk','dkim01','dkim02','mx','news','newsletter','send','postmark'
];
const DKIM_SCAN_CONCURRENCY = 8;
const state = { report:null };

const $ = id => document.getElementById(id);
const esc = (s='') => String(s).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));

function normalizeDomain(value) {
  let v=String(value||'').trim().toLowerCase().replace(/^https?:\/\//,'').split('/')[0].split(':')[0].replace(/\.$/,'');
  if(!v || v.length>253 || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/i.test(v)) throw new Error('Skriv inn et gyldig domene, for eksempel eksempel.no.');
  return v;
}

async function dnsQuery(name,type,opts={}) {
  const qtype = TYPES[type] || type;
  const params=new URLSearchParams({name,type:String(qtype),do:opts.do===false?'false':'true'});
  if(opts.cd) params.set('cd','true');
  const res=await fetch(`${DOH_ENDPOINT}?${params}`,{headers:{accept:'application/dns-json'},cache:'no-store'});
  if(!res.ok) throw new Error(`DNS-tjeneren svarte med HTTP ${res.status}.`);
  return res.json();
}
function answers(r,type){const n=TYPES[type]||type;return (r?.Answer||[]).filter(x=>x.type===n);}
function txtValues(r){return answers(r,'TXT').map(x=>String(x.data).replace(/^"|"$/g,'').replace(/"\s+"/g,''));}
function firstTxt(r,prefix){return txtValues(r).find(v=>v.toLowerCase().startsWith(prefix.toLowerCase()))||'';}
function parseTags(record){const out={};String(record||'').split(';').map(x=>x.trim()).filter(Boolean).forEach(p=>{const i=p.indexOf('=');if(i>0)out[p.slice(0,i).trim().toLowerCase()]=p.slice(i+1).trim();});return out;}
function check(severity,label,subtitle,detail,records=[],factor=0,extra={}){return {severity,label,subtitle,detail,records,factor,...extra};}
function cleanHost(s){return String(s||'').replace(/\.$/,'');}
function mxRows(r){return answers(r,'MX').map(x=>{const m=String(x.data).match(/^(\d+)\s+(.+)$/);return m?{priority:Number(m[1]),host:cleanHost(m[2])}:{priority:0,host:cleanHost(x.data)};}).sort((a,b)=>a.priority-b.priority);}

function dnsHost(value=''){return String(value||'').trim().toLowerCase().replace(/^\d+\s+/,'').replace(/\.$/,'');}
function mxHosts(r){return answers(r,'MX').map(x=>dnsHost(x.data)).filter(Boolean);}
function nsHosts(r){return answers(r,'NS').map(x=>dnsHost(x.data)).filter(Boolean);}
function cnameHosts(r){return answers(r,'CNAME').map(x=>dnsHost(x.data)).filter(Boolean);}
function validDkimRecord(record){const tags=parseTags(record);return Boolean(tags.p&&tags.p.trim());}
function revokedDkimRecord(record){const tags=parseTags(record);return Object.prototype.hasOwnProperty.call(tags,'p')&&!tags.p.trim();}
function dkimTxtRecords(r){return txtValues(r).filter(v=>/^v=DKIM1\b/i.test(v)||/(?:^|;)\s*p\s*=/.test(v));}
function unique(values){return [...new Set(values.filter(Boolean))];}

function detectProviders(mxResult,nsResult,rootTxtResult){
  const mx=mxHosts(mxResult), ns=nsHosts(nsResult), rootTxt=txtValues(rootTxtResult).join(' ').toLowerCase(), providers=[];
  const add=(id,name,evidence,selectors=[],extra={})=>{if(!evidence.length||providers.some(p=>p.id===id))return;providers.push({id,name,evidence,selectors,...extra});};

  const isDsMx=h=>h==='mx.domeneshop.no'||h.endsWith('.domeneshop.no');
  const isDsNs=h=>/^ns[123]\.hyp\.net$/.test(h)||h.endsWith('.domeneshop.no');
  const dsMx=mx.some(isDsMx), dsNs=ns.some(isDsNs);
  const dsMxManaged=mx.length>0&&mx.every(isDsMx), dsNsManaged=ns.length>=2&&ns.every(isDsNs);
  const dsSpf=rootTxt.includes('_spf.domeneshop.no');
  add('domeneshop','Domeneshop',[dsMx?'MX: mx.domeneshop.no':'',dsNs?'NS: ns1/ns2/ns3.hyp.net':'',dsSpf?'SPF: _spf.domeneshop.no':''].filter(Boolean),[],{autoDkim:Boolean(dsMxManaged&&dsNsManaged),confidence:dsMxManaged&&dsNsManaged?'high':'medium'});

  const isOneMx=h=>h==='mx.one.com'||h.endsWith('.mx.one.com')||h.endsWith('.mx.service.one')||/^mx\d+\.pub\.mailpod[0-9a-z-]*\.one\.com$/.test(h);
  const isOneNs=h=>/^(?:ns0?[12]|ns[12])\.one\.com$/.test(h);
  const oneMx=mx.some(isOneMx), oneNs=ns.some(isOneNs);
  const oneMxManaged=mx.length>0&&mx.every(isOneMx), oneNsManaged=ns.length>=2&&ns.every(isOneNs);
  const oneSpf=rootTxt.includes('_custspf.one.com');
  add('onecom','one.com',[oneMx?'MX: one.com':'',oneNs?'NS: ns01/ns02.one.com':'',oneSpf?'SPF: _custspf.one.com':''].filter(Boolean),[],{autoDkim:Boolean(oneMxManaged&&oneNsManaged),confidence:oneMxManaged&&oneNsManaged?'high':'medium',opaqueSelectors:true});

  const m365Mx=mx.some(h=>h.endsWith('.mail.protection.outlook.com')), m365Spf=rootTxt.includes('spf.protection.outlook.com');
  add('microsoft365','Microsoft 365',[m365Mx?'MX: mail.protection.outlook.com':'',m365Spf?'SPF: spf.protection.outlook.com':''].filter(Boolean),['selector1','selector2']);

  const googleMx=mx.some(h=>h==='aspmx.l.google.com'||h.endsWith('.google.com')||h.endsWith('.googlemail.com')), googleSpf=rootTxt.includes('_spf.google.com');
  add('google','Google Workspace',[googleMx?'MX: Google':'',googleSpf?'SPF: _spf.google.com':''].filter(Boolean),['google']);

  const sendgrid=rootTxt.includes('sendgrid.net')||mx.some(h=>h.endsWith('.sendgrid.net'));
  add('sendgrid','SendGrid',[sendgrid?'SPF/MX: sendgrid.net':''].filter(Boolean),['s1','s2']);

  const brevo=rootTxt.includes('spf.sendinblue.com')||rootTxt.includes('spf.brevo.com')||rootTxt.includes('sendinblue.com');
  add('brevo','Brevo',[brevo?'SPF: Brevo/Sendinblue':''].filter(Boolean),[]);

  const mailgun=rootTxt.includes('mailgun.org')||mx.some(h=>h.endsWith('.mailgun.org'));
  add('mailgun','Mailgun',[mailgun?'SPF/MX: mailgun.org':''].filter(Boolean),['s1','s2']);

  const postmark=rootTxt.includes('spf.mtasv.net')||rootTxt.includes('postmarkapp.com');
  add('postmark','Postmark',[postmark?'SPF: mtasv.net/Postmark':''].filter(Boolean),['postmark']);

  const ses=rootTxt.includes('amazonses.com')||mx.some(h=>h.endsWith('.amazonses.com'));
  add('amazonses','Amazon SES',[ses?'SPF/MX: amazonses.com':''].filter(Boolean),[],{opaqueSelectors:true});

  const mailchimp=rootTxt.includes('servers.mcsv.net')||rootTxt.includes('spf.mandrillapp.com')||rootTxt.includes('mandrillapp.com');
  add('mailchimp','Mailchimp / Mandrill',[mailchimp?'SPF: Mailchimp/Mandrill':''].filter(Boolean),['k1','k2','k3','mandrill']);
  return providers;
}

async function mapLimit(items,limit,worker){
  const out=new Array(items.length);let next=0;
  const runners=Array.from({length:Math.min(limit,items.length)},async()=>{while(true){const i=next++;if(i>=items.length)return;out[i]=await worker(items[i],i);}});
  await Promise.all(runners);return out;
}
async function resolveDkimTarget(name,depth=0,seen=new Set()){
  const normalized=dnsHost(name);
  if(!normalized||depth>4||seen.has(normalized))return {txt:[],chain:[],error:'CNAME-kjeden kunne ikke løses sikkert'};
  seen.add(normalized);
  const [txtResult,cnameResult]=await Promise.all([dnsQuery(normalized,'TXT'),dnsQuery(normalized,'CNAME')]);
  const txt=dkimTxtRecords(txtResult);
  if(txt.length)return {txt,chain:[],raw:{txt:txtResult,cname:cnameResult}};
  const targets=cnameHosts(cnameResult);
  if(!targets.length)return {txt:[],chain:[],raw:{txt:txtResult,cname:cnameResult}};
  const target=targets[0], child=await resolveDkimTarget(target,depth+1,seen);
  return {txt:child.txt,chain:[target,...(child.chain||[])],raw:{txt:txtResult,cname:cnameResult,child:child.raw},error:child.error};
}
async function lookupDkimSelector(domain,selector){
  const host=`${selector}._domainkey.${domain}`;
  try{
    const resolved=await resolveDkimTarget(host), records=resolved.txt||[], valid=records.filter(validDkimRecord), revoked=records.filter(revokedDkimRecord), hasCname=(resolved.chain||[]).length>0;
    let state='none';if(valid.length)state='valid';else if(revoked.length)state='revoked';else if(records.length||hasCname)state='broken';
    return {selector,host,state,records,cnameChain:resolved.chain||[],error:resolved.error||'',raw:resolved.raw};
  }catch(err){return {selector,host,state:'lookup-error',records:[],cnameChain:[],error:err?.message||String(err)};}
}
function providerSelectorList(providers){return unique(providers.flatMap(p=>p.selectors||[]));}

function evalDnssec(base,ds,dnskey){
  const dsRows=answers(ds,'DS'), keys=answers(dnskey,'DNSKEY');
  if(dsRows.length && base?.AD===true) return check('good','Validert','DNSSEC er aktivt og validert','Resolveren returnerte autentisert DNS-data (AD) og domenet har DS-poster.',dsRows.map(x=>x.data),1);
  if(dsRows.length && base?.AD!==true) return check('bad','Validerer ikke','DS finnes, men DNSSEC ble ikke validert','Dette kan bety en DNSSEC-feil eller en ugyldig kjede mellom DS og DNSKEY.',dsRows.map(x=>x.data),0);
  if(keys.length) return check('warn','Ufullstendig','DNSKEY finnes, men ingen DS ble funnet','DNSSEC-sonen ser signert ut, men tillitskjeden er ikke publisert hos overordnet sone.',keys.map(x=>x.data),.35);
  return check('warn','Ikke aktivert','DNSSEC ble ikke funnet','DNSSEC beskytter DNS-svar mot manipulering og er også en forutsetning for sikker DANE/TLSA.',[],.2);
}
function evalSpf(r){
  const rows=txtValues(r).filter(v=>/^v=spf1\b/i.test(v));
  if(rows.length>1) return check('bad','Flere SPF-poster',`${rows.length} SPF-poster funnet`,'Et domene skal normalt publisere én samlet SPF-policy. Flere v=spf1-poster kan gi PermError.',rows,0);
  if(!rows.length) return check('bad','Mangler','Ingen SPF-policy funnet','SPF bør angi hvilke systemer som har lov til å sende e-post for domenet.',[],0);
  const rec=rows[0], mech=(rec.match(/\s([~?+-])all\b/i)||[])[1];
  if(mech==='-') return check('good','Sterk policy','SPF avsluttes med -all','Uautoriserte avsendere faller utenfor SPF-policyen.',rec? [rec]:[],1);
  if(mech==='~') return check('warn','Softfail','SPF avsluttes med ~all','Policyen er publisert, men softfail er mindre tydelig enn -all når alle legitime avsendere er kjent.',[rec],.75);
  return check('warn','Bør vurderes','SPF finnes, men avslutningen er svak eller uklar','Kontroller at alle legitime avsendere er med og vurder en tydelig avslutning.',[rec],.6);
}
function evalDkim(lookups,providers){
  const valid=(lookups||[]).filter(x=>x.state==='valid');
  const broken=(lookups||[]).filter(x=>x.state==='broken'||x.state==='revoked');
  const lookupErrors=(lookups||[]).filter(x=>x.state==='lookup-error');
  const providerNames=(providers||[]).map(p=>p.name);
  const providerText=providerNames.length?` Identifisert e-postleverandør: ${providerNames.join(', ')}.`:'';

  if(valid.length){
    const records=valid.flatMap(x=>x.records.map(r=>`${x.selector}${x.cnameChain.length?` -> ${x.cnameChain.join(' -> ')}`:''}: ${r}`));
    return check('good','Verifisert',`${valid.length} DKIM-selector${valid.length===1?'':'er'} verifisert`,`Minst én gyldig offentlig DKIM-nøkkel ble funnet. TXT og CNAME-kjeder kontrolleres.${providerText}`,records,1,{found:valid,broken,verificationMethod:'dns',providers:providerNames});
  }
  if(broken.length){
    const records=broken.map(x=>`${x.selector}${x.cnameChain.length?` -> ${x.cnameChain.join(' -> ')}`:''}: ${x.state==='revoked'?'tom offentlig nøkkel (p=)':'CNAME/TXT ble funnet, men ingen gyldig offentlig nøkkel kunne valideres'}`);
    return check('bad','DKIM-feil','DKIM-post funnet, men valideringen feilet',`Mail Security Score fant en eksplisitt DKIM-post eller CNAME-kjede, men kunne ikke validere en aktiv offentlig nøkkel.${providerText}`,records,0,{found:[],broken,verificationMethod:'dns-error',providers:providerNames});
  }

  const domeneshop=(providers||[]).find(p=>p.id==='domeneshop'&&p.autoDkim);
  if(domeneshop)return check('good','Automatisk aktivert','Domeneshop håndterer DNS og e-post','MX peker til mx.domeneshop.no og autoritative navneservere peker til Domeneshops ns1/ns2/ns3.hyp.net. Domeneshop oppgir at SPF, DKIM og DMARC settes opp automatisk når alle tjenestene ligger hos dem. Statusen er derfor bekreftet via leverandøroppsett selv om en unik DKIM-selector ikke ble oppdaget automatisk.',['Provider: Domeneshop','Deteksjon: MX + autoritative NS','DKIM: automatisk administrert av Domeneshop'],1,{found:[],broken:[],verificationMethod:'provider-assurance',providers:['Domeneshop']});

  const onecom=(providers||[]).find(p=>p.id==='onecom');
  if(onecom?.autoDkim)return check('good','Automatisk aktivert','one.com håndterer DNS og e-post','MX peker til one.com sine e-postservere og autoritative navneservere er one.com sine ns01/ns02.one.com. one.com oppgir at DKIM aktiveres automatisk når både deres navneservere og e-postservere brukes. Statusen er derfor bekreftet via leverandøroppsett selv om de leverandørstyrte DKIM-selectorene ikke ble oppdaget automatisk.',['Provider: one.com','Deteksjon: MX + autoritative NS','DKIM: automatisk administrert av one.com'],1,{found:[],broken:[],verificationMethod:'provider-assurance',providers:['one.com']});

  const ses=(providers||[]).some(p=>p.id==='amazonses');
  const onecomExternal=(providers||[]).some(p=>p.id==='onecom'&&!p.autoDkim);
  const detail=onecomExternal
    ? `one.com ble identifisert som e-postleverandør, men domenet bruker ikke et komplett one.com-navneserveroppsett. one.com bruker domenespesifikke DKIM CNAME-poster når eksterne navneservere brukes, og disse selectorene kan ikke oppdages eller gjettes sikkert fra domenenavnet alene. Kontroller de konkrete DKIM-postene one.com har oppgitt for domenet.${providerText}`
    : ses
      ? `Ingen gyldig DKIM-nøkkel ble funnet med selectorene som ble testet. Amazon SES kan bruke unike Easy DKIM-selector-tokens som ikke kan gjettes fra domenenavnet alene.${providerText}`
      : `Ingen gyldig DKIM-nøkkel ble funnet med kjente eller leverandørspesifikke selectorer. DKIM-selectorer er ikke standardiserte, så dette beviser ikke at domenet mangler DKIM.${providerText}`;
  const errorNote=lookupErrors.length?` ${lookupErrors.length} selector-oppslag fikk i tillegg en DNS-/nettverksfeil.`:'';
  return check('warn','Kunne ikke bekreftes','Ingen kjent DKIM-selector ble verifisert',detail+errorNote,[],.5,{found:[],broken:[],verificationMethod:'not-confirmed',providers:providerNames,lookupErrors});
}
function evalDmarc(r){
  const rec=firstTxt(r,'v=DMARC1');
  if(!rec) return check('bad','Mangler','Ingen DMARC-policy funnet','DMARC forteller mottakere hvordan meldinger som ikke passerer autentisering og alignment skal håndteres.',[],0);
  const t=parseTags(rec), p=(t.p||'none').toLowerCase(), pct=Number(t.pct||100);
  if(p==='reject' && pct===100) return check('good','Reject','DMARC håndheves fullt ut','p=reject og pct=100 gir den tydeligste policyen mot spoofing når alle legitime avsendere er riktig konfigurert.',[rec],1);
  if(p==='quarantine') return check('warn','Quarantine','DMARC håndheves delvis','p=quarantine er et godt mellomsteg før p=reject.',[rec],.82);
  if(p==='reject' && pct<100) return check('warn','Delvis reject',`DMARC gjelder ${pct}% av trafikken`,'Øk pct gradvis når du har kontroll på alle legitime avsendere.',[rec],.82);
  return check('warn','Overvåking','DMARC står i p=none','Rapportering er aktiv, men policyen ber ikke mottakere om å blokkere eller karantenesette feilende meldinger.',[rec],.55);
}
function evalMtaSts(r){const rec=firstTxt(r,'v=STSv1');return rec?check('good','Publisert','MTA-STS DNS-post funnet','Domenet annonserer MTA-STS. Den statiske kontrollen kan ikke lese policyfilen på tvers av alle nettsteder på grunn av nettleserbegrensninger.',[rec],1):check('warn','Mangler','Ingen MTA-STS-post','MTA-STS kan hjelpe avsendende servere med å kreve autentisert TLS ved levering.',[],0);}
function evalTlsRpt(r){const rec=firstTxt(r,'v=TLSRPTv1');return rec?check('good','Aktivert','SMTP TLS-RPT er publisert','Domenet annonserer hvor rapporter om TLS-feil skal sendes.',[rec],1):check('warn','Mangler','Ingen TLS-RPT-post','TLS-RPT gir synlighet i feil på SMTP TLS og transportpolicy.',[],0);}
function evalCaa(r){const rows=answers(r,'CAA').map(x=>x.data);return rows.length?check('good','Publisert',`${rows.length} CAA-post${rows.length===1?'':'er'}`,'CAA begrenser hvilke sertifikatutstedere som kan utstede sertifikater for domenet.',rows,1):check('info','Ikke satt','Ingen CAA-policy funnet','CAA er ikke påkrevd, men kan redusere risikoen for uønsket sertifikatutstedelse.',[],.55);}
function evalBimi(r){const rec=firstTxt(r,'v=BIMI1');return rec?check('good','Publisert','BIMI-post funnet','BIMI kan støtte merkevareindikasjon hos kompatible mottakere.',[rec],1):check('info','Valgfritt','Ingen BIMI-post funnet','BIMI er et valgfritt tillegg og har lav vekt i scoren.',[],.75);}
function evalMxRedundancy(mx){
  const rows=mxRows(mx), real=rows.filter(x=>x.host!=='.');
  if(rows.some(x=>x.host==='.')) return check('info','Null MX','Domenet annonserer at det ikke mottar e-post','MX 0 . brukes for domener som eksplisitt ikke skal motta e-post.',rows.map(x=>`${x.priority} ${x.host}`),.8,{rows});
  if(real.length===1) return check('good','Konfigurert','1 MX-post – gyldig oppsett','Én gyldig MX-post er en normal og korrekt konfigurasjon. Flere MX-poster er bare nødvendig når e-postleverandøren bruker flere mottaksservere, for eksempel for redundans.',real.map(x=>`${x.priority} ${x.host}`),1,{rows:real});
  if(real.length>1) return check('good','Konfigurert',`${real.length} MX-poster – gyldig oppsett`,'MX-postene er gyldige og angir hvilke servere som mottar e-post for domenet. Antall MX-poster styres av e-postleverandørens arkitektur og er ikke i seg selv et kvalitetskrav.',real.map(x=>`${x.priority} ${x.host}`),1,{rows:real});
  return check('bad','Mangler','Ingen MX-servere funnet','Domenet har ingen vanlig MX-konfigurasjon for mottak av e-post.',[],0,{rows:[]});
}
function evalIpv6(mxDetails){
  if(!mxDetails.length) return check('info','Ikke relevant','Ingen mottakende MX-servere å teste','IPv6-støtte vurderes på MX-serverne.',[],.8);
  const enabled=mxDetails.filter(x=>x.aaaa.length>0);
  if(enabled.length===mxDetails.length) return check('good','Full støtte',`${enabled.length}/${mxDetails.length} MX-servere har IPv6`,'Alle testede MX-servere har AAAA-adresser.',enabled.flatMap(x=>x.aaaa.map(a=>`${x.host}: ${a}`)),1);
  if(enabled.length) return check('info','Delvis støtte',`${enabled.length}/${mxDetails.length} MX-servere har IPv6`,'Minst én MX-server kan nås via IPv6.',enabled.flatMap(x=>x.aaaa.map(a=>`${x.host}: ${a}`)),.8);
  return check('info','Kun IPv4','Ingen MX-servere med IPv6 funnet','IPv6 er ikke et krav for sikker e-post, men kan forbedre nettverksstøtte og modernitet.',[],.55);
}
function evalDnsConfig(ns,soa,a,aaaa){
  const nss=answers(ns,'NS').map(x=>cleanHost(x.data)), soas=answers(soa,'SOA'), addr=[...answers(a,'A'),...answers(aaaa,'AAAA')];
  if(nss.length>=2 && soas.length) return check('good','Sunn','Autoritativ DNS ser grunnleggende robust ut',`${nss.length} navneservere og SOA-post ble funnet.${addr.length?' Domenet har også adresseposter.':''}`,nss,1,{nss});
  if(nss.length===1) return check('warn','Lite redundant','Kun én autoritativ navneserver funnet','Flere autoritative navneservere gir bedre DNS-robusthet.',nss,.5,{nss});
  return check('bad','Ufullstendig','DNS-grunnkonfigurasjonen mangler sentrale poster','Kontroller autoritative navneservere og SOA-konfigurasjon.',nss,0,{nss});
}
function evalDane(mxDetails,dnssec){
  const tlsa=mxDetails.flatMap(x=>x.tlsa.map(v=>({host:x.host,value:v,validated:x.tlsaAD})));
  if(tlsa.length && dnssec.factor>=1 && tlsa.every(x=>x.validated)) return check('good','DANE aktivt',`${tlsa.length} validerte TLSA-post${tlsa.length===1?'':'er'}`,'TLSA-poster på SMTP port 25 ble validert med DNSSEC. Dette kan binde SMTP TLS-identiteten til DNSSEC.',tlsa.map(x=>`_25._tcp.${x.host}: ${x.value}`),1,{tlsa});
  if(tlsa.length) return check('bad','TLSA uten sikker kjede','TLSA finnes, men kan ikke stoles på via DNSSEC','DANE krever en gyldig DNSSEC-kjede. TLSA uten DNSSEC-validering gir ikke den tilsiktede autentiseringen.',tlsa.map(x=>`_25._tcp.${x.host}: ${x.value}`),0,{tlsa});
  return check('info','Ikke aktivert','Ingen DANE/TLSA-poster funnet','DANE for SMTP er en avansert tilleggsmekanisme. Den krever DNSSEC og TLSA-poster for MX-serverne.',[],.45,{tlsa:[]});
}
async function checkHttpsCertificate(domain){
  const controller=new AbortController(); const timer=setTimeout(()=>controller.abort(),7000);
  try { await fetch(`https://${domain}/`,{mode:'no-cors',cache:'no-store',redirect:'follow',signal:controller.signal}); clearTimeout(timer); return check('good','Betrodd','HTTPS/TLS kunne valideres av nettleseren','Nettleseren klarte å opprette en HTTPS-forbindelse uten sertifikatfeil. Denne klientkontrollen viser ikke utløpsdato eller SMTP-sertifikatet.',[],1,{limited:true}); }
  catch(e){ clearTimeout(timer); return check('warn','Ikke bekreftet','HTTPS/TLS kunne ikke bekreftes','Dette kan skyldes manglende nettsted, nettverksblokkering eller sertifikat/TLS-feil. Kontrollen gjelder HTTPS på rotdomenet, ikke SMTP STARTTLS.',[],.45,{limited:true}); }
}

async function scanDomain(domain,selectorInput,scanCommon){
  $('loadingText').textContent='Henter DNS, e-postpolicyer og sertifikatstatus';
  const special={dmarc:`_dmarc.${domain}`,mtasts:`_mta-sts.${domain}`,tlsrpt:`_smtp._tls.${domain}`,bimi:`default._bimi.${domain}`};
  const certificatePromise=checkHttpsCertificate(domain);
  const [a,aaaa,ns,soa,mx,txt,ds,dnskey,caa,dmarc,mtasts,tlsrpt,bimi]=await Promise.all([
    dnsQuery(domain,'A'),dnsQuery(domain,'AAAA'),dnsQuery(domain,'NS'),dnsQuery(domain,'SOA'),dnsQuery(domain,'MX'),dnsQuery(domain,'TXT'),dnsQuery(domain,'DS'),dnsQuery(domain,'DNSKEY'),dnsQuery(domain,'CAA'),dnsQuery(special.dmarc,'TXT'),dnsQuery(special.mtasts,'TXT'),dnsQuery(special.tlsrpt,'TXT'),dnsQuery(special.bimi,'TXT')
  ]);
  const mxBase=mxRows(mx).filter(x=>x.host!=='.');
  $('loadingText').textContent=`Tester ${mxBase.length} MX-server${mxBase.length===1?'':'e'} for IPv6 og DANE/TLSA`;
  const mxDetails=await Promise.all(mxBase.map(async row=>{
    const [aaaaR,tlsaR]=await Promise.all([dnsQuery(row.host,'AAAA'),dnsQuery(`_25._tcp.${row.host}`,'TLSA')]);
    return {...row,aaaa:answers(aaaaR,'AAAA').map(x=>x.data),tlsa:answers(tlsaR,'TLSA').map(x=>x.data),tlsaAD:tlsaR.AD===true};
  }));
  const providers=detectProviders(mx,ns,txt);
  let selectors=[]; const customProvided=Boolean(selectorInput.trim());
  if(customProvided) selectors.push(...selectorInput.split(',').map(s=>s.trim()).filter(Boolean));
  selectors.push(...providerSelectorList(providers));
  const providerAssuredDkim=providers.some(p=>p.autoDkim);
  if(scanCommon&&!providerAssuredDkim) selectors.push(...commonSelectors);
  selectors=unique(selectors.map(s=>s.replace(/\._domainkey.*$/,'').toLowerCase()).filter(s=>/^[a-z0-9_-]{1,63}$/i.test(s))).slice(0,48);
  $('loadingText').textContent=selectors.length?`Sjekker ${selectors.length} DKIM-selector${selectors.length===1?'':'er'} (TXT + CNAME)`:'Vurderer e-postleverandør og policyer';
  const dkimLookups=selectors.length?await mapLimit(selectors,DKIM_SCAN_CONCURRENCY,s=>lookupDkimSelector(domain,s)):[];
  const dnssec=evalDnssec(a,ds,dnskey);
  const certificate=await certificatePromise;
  const checks={
    dnssec,
    spf:evalSpf(txt),
    dkim:evalDkim(dkimLookups,providers),
    dmarc:evalDmarc(dmarc),
    mtasts:evalMtaSts(mtasts),
    tlsrpt:evalTlsRpt(tlsrpt),
    dane:evalDane(mxDetails,dnssec),
    caa:evalCaa(caa),
    bimi:evalBimi(bimi),
    mxredundancy:evalMxRedundancy(mx),
    ipv6mail:evalIpv6(mxDetails),
    dnsconfig:evalDnsConfig(ns,soa,a,aaaa),
    certificate
  };
  return {domain,scannedAt:new Date().toISOString(),selectorsChecked:selectors,providers,checks,mxDetails,raw:{a,aaaa,ns,soa,mx,txt,ds,dnskey,caa,dmarc,mtasts,tlsrpt,bimi,dkim:dkimLookups.map(x=>x.raw)}};
}

const META={
  dnssec:['DNSSEC','DNS-integritet'],spf:['SPF','Autoriserte avsendere'],dkim:['DKIM','Signering av utgående e-post'],dmarc:['DMARC','Policy mot spoofing'],mtasts:['MTA-STS','TLS-policy for SMTP'],tlsrpt:['TLS-RPT','Rapportering av TLS-feil'],dane:['DANE/TLSA','DNSSEC-bundet SMTP TLS'],caa:['CAA','Sertifikatutstedere'],bimi:['BIMI','Merkevareindikasjon'],mxredundancy:['MX-konfigurasjon','E-postruting'],ipv6mail:['IPv6 e-post','Nettverksstøtte'],dnsconfig:['DNS-konfigurasjon','Autoritativ robusthet'],certificate:['Sertifikatstatus','HTTPS/TLS på domenet']
};
const ICON={good:'✓',warn:'!',bad:'×',info:'i'};

function totalScore(checks){return Math.round(Object.entries(WEIGHTS).reduce((sum,[k,w])=>sum+w*Math.max(0,Math.min(1,checks[k]?.factor??0)),0));}
function scoreLabel(s){return s>=90?'Svært sterk':s>=80?'Sterk':s>=65?'God':s>=50?'Bør forbedres':'Svak';}
function earned(k,c){return Math.round(WEIGHTS[k]*c.factor*10)/10;}
function gap(k,c){return Math.round((WEIGHTS[k]-WEIGHTS[k]*c.factor)*10)/10;}

function recommendationFor(key,c,domain){
  const map={
    dmarc:['Styrk DMARC-policyen',c.label==='Mangler'?`Publiser først en DMARC-post på _dmarc.${domain} med p=none og rapportering. Når alle legitime avsendere er bekreftet, gå gradvis til quarantine og reject.`:'Når DMARC-rapportene viser at legitim e-post passerer, øk håndhevingen mot p=reject og pct=100.'],
    spf:['Rydd opp i SPF',c.label==='Mangler'?'Kartlegg alle tjenester som sender e-post for domenet og publiser én samlet v=spf1-post.':'Kontroller alle include/ip-mekanismer og avslutningen av SPF-policyen.'],
    dkim:['Bekreft DKIM',c.verificationMethod==='not-confirmed'?'Finn korrekt DKIM-selector hos e-postleverandøren eller fra DKIM-Signature-headeren i en sendt e-post, og test den eksplisitt. Manglende automatisk funn betyr ikke at DKIM mangler.':'Kontroller DKIM-posten som ble funnet mot e-postleverandørens forventede TXT- eller CNAME-verdi.'],
    dnssec:['Aktiver eller reparer DNSSEC','Aktiver DNSSEC hos DNS-leverandøren og sørg for at korrekt DS-post er publisert hos registraren. DANE/TLSA er avhengig av dette.'],
    mtasts:['Aktiver MTA-STS','Publiser _mta-sts TXT-posten og en gyldig policy på mta-sts.<domene> slik at avsendere kan kreve autentisert TLS.'],
    tlsrpt:['Aktiver TLS-RPT',`Publiser en TXT-post på _smtp._tls.${domain} med v=TLSRPTv1 og en rapportadresse du faktisk mottar eller analyserer.`],
    dane:['Vurder DANE/TLSA','Når DNSSEC er stabilt, publiser TLSA-poster på _25._tcp for MX-serverne og sørg for at de matcher SMTP-sertifikatet.'],
    caa:['Publiser CAA','Begrens hvilke sertifikatutstedere som får utstede sertifikater for domenet med CAA.'],
    bimi:['Vurder BIMI','Hvis domenet har sterk DMARC-håndheving, kan BIMI brukes som et valgfritt merkevarelag hos støttede mottakere.'],
    mxredundancy:['Konfigurer MX','Publiser MX-posten eller MX-postene e-postleverandøren krever. Én gyldig MX-post er en normal og korrekt konfigurasjon når leverandøren bruker ett mottaksmål.'],
    ipv6mail:['Vurder IPv6 på MX','Hvis e-postplattformen støtter IPv6, publiser AAAA-adresser for MX-serverne og test SMTP over IPv6 før aktivering.'],
    dnsconfig:['Styrk DNS-grunnlaget','Bruk minst to autoritative navneservere og kontroller SOA/delegering hos registraren.'],
    certificate:['Kontroller HTTPS/TLS','Test domenets sertifikat i nettleser eller et dedikert TLS-verktøy. Denne statiske appen kan bare bekrefte om nettleseren klarer en betrodd HTTPS-forbindelse.']
  };
  const [title,body]=map[key]||['Forbedre konfigurasjonen',c.detail];
  return {key,title,body,points:gap(key,c)};
}
function recommendations(report){return Object.entries(report.checks).map(([k,c])=>recommendationFor(k,c,report.domain)).filter(x=>x.points>.4).sort((a,b)=>b.points-a.points).slice(0,3);}

function fixData(key,c,domain){
  if(c.factor>=.99) return null;
  const common={
    dmarc:{title:'Forslag til trygg DMARC-utrulling',steps:['Start med p=none og samle rapporter.','Bekreft at alle legitime avsendere passerer SPF/DKIM med alignment.','Flytt gradvis til p=quarantine.','Bruk p=reject når legitim trafikk er under kontroll.'],record:{name:`_dmarc.${domain}`,type:'TXT',value:`v=DMARC1; p=none; rua=mailto:dmarc@${domain}; pct=100`},warning:`dmarc@${domain} er bare et eksempel. Bruk en adresse eller rapporttjeneste som faktisk tar imot DMARC-rapporter.`},
    spf:{title:'Slik bygger du SPF riktig',steps:['Lag liste over alle systemer som sender e-post for domenet.','Hent offisiell SPF include-verdi fra hver leverandør.','Slå alt sammen i én v=spf1-post.','Test før du strammer til -all.'],record:{name:domain,type:'TXT',value:'v=spf1 include:<VERDI-FRA-E-POSTLEVERANDØR> -all'},warning:'Ikke kopier plassholderen direkte. Feil SPF kan blokkere legitim e-post.'},
    dkim:c.verificationMethod==='not-confirmed'?{title:'Slik bekrefter du DKIM',steps:['Finn DKIM-selectoren hos e-postleverandøren, eller les s=-verdien i DKIM-Signature-headeren fra en faktisk sendt e-post.','Skriv selectoren i DKIM-feltet i Mail Security Score og kjør testen på nytt.','Hvis leverandørens kontrollpanel sier at DKIM ikke er aktivert, aktiver DKIM og publiser nøyaktig TXT- eller CNAME-posten leverandøren oppgir.'],record:null,warning:'Ikke opprett en ny DKIM-post bare fordi Mail Security Score ikke fant en kjent selector. Manglende automatisk funn er ikke det samme som at DKIM mangler.'}:{title:'Slik retter du DKIM-feilen',steps:['Kontroller DKIM-selectoren som ble funnet og sammenlign den med verdien hos e-postleverandøren.','Hvis posten er en CNAME, kontroller at hele CNAME-kjeden peker til en aktiv DKIM-nøkkel.','Hvis p= er tom, er nøkkelen tilbakekalt og må erstattes eller roteres hos leverandøren.','Publiser leverandørens korrekte TXT- eller CNAME-verdi og test på nytt.'],record:{name:`<selector>._domainkey.${domain}`,type:'TXT eller CNAME',value:'<KORREKT-VERDI-FRA-E-POSTLEVERANDØREN>'},warning:'Ikke generer eller endre DKIM-nøkkelen manuelt med mindre e-postplattformen eksplisitt krever det.'},
    tlsrpt:{title:'Aktiver SMTP TLS-rapportering',steps:['Opprett en adresse eller rapporttjeneste som mottar TLS-RPT.','Publiser TXT-posten under _smtp._tls.','Følg opp rapporterte TLS-feil.'],record:{name:`_smtp._tls.${domain}`,type:'TXT',value:`v=TLSRPTv1; rua=mailto:tlsrpt@${domain}`},warning:`tlsrpt@${domain} er et eksempel og må eksistere eller erstattes.`},
    mtasts:{title:'Aktiver MTA-STS',steps:['Publiser _mta-sts TXT-posten med en policy-ID.','Sett opp HTTPS på mta-sts-domenet.','Publiser /.well-known/mta-sts.txt med korrekt MX-mønster.','Start gjerne i testing-modus før enforce.'],record:{name:`_mta-sts.${domain}`,type:'TXT',value:'v=STSv1; id=20260810'},warning:'MTA-STS krever også en policyfil over HTTPS. MX-verdier må tilpasses e-postleverandøren.'},
    dane:{title:'Aktiver DANE for SMTP',steps:['Sørg først for fullt validert DNSSEC.','Hent riktig sertifikat/SPKI-hash fra hver SMTP MX-server.','Publiser TLSA på _25._tcp.<mx-host>.','Test at TLSA fortsatt matcher etter sertifikatfornyelser.'],record:{name:'_25._tcp.<mx-server>',type:'TLSA',value:'<usage> <selector> <matching-type> <sertifikatdata>'},warning:'Ikke publiser en tilfeldig TLSA-verdi. Feil TLSA kan føre til leveringsproblemer hos DANE-validerende avsendere.'},
    dnssec:{title:'Aktiver eller reparer DNSSEC',steps:['Aktiver DNSSEC hos autoritativ DNS-leverandør.','Publiser korrekt DS hos domeneregistraren.','Vent på propagasjon og test validering på nytt.'],record:null,warning:'Feil DS kan gjøre domenet utilgjengelig for DNSSEC-validerende klienter.'}
  };
  return common[key]||null;
}

function render(report){
  const score=totalScore(report.checks); state.report={...report,score,recommendations:recommendations(report)};
  $('resultDomain').textContent=report.domain;
  $('scanTime').textContent=`Kontrollert ${new Intl.DateTimeFormat('nb-NO',{dateStyle:'long',timeStyle:'short'}).format(new Date(report.scannedAt))}`;
  $('scoreNumber').textContent=score; $('scoreLabel').textContent=scoreLabel(score); $('scoreRing').style.setProperty('--score',`${score*3.6}deg`);
  renderRecommendations(state.report); renderSummary(report.checks); renderBreakdown(report.checks); renderChecks(report); renderAside(report);
  $('results').classList.remove('hidden');
  requestAnimationFrame(()=>$('results').scrollIntoView({behavior:'smooth',block:'start'}));
}
function renderRecommendations(report){
  const recs=report.recommendations; $('recommendationCount').textContent=recs.length; const total=Math.round(recs.reduce((s,r)=>s+r.points,0)); $('potentialBadge').textContent=`Mulig +${total} poeng`;
  $('topRecommendations').innerHTML=recs.length?recs.map((r,i)=>`<article class="recommendation-card"><div class="rec-top"><span class="rec-number">0${i+1}</span><span class="rec-points">+${Math.round(r.points)} poeng mulig</span></div><h4>${esc(r.title)}</h4><p>${esc(r.body)}</p><button type="button" data-jump="${esc(r.key)}">Se teknisk detalj →</button></article>`).join(''):`<article class="recommendation-card"><div class="rec-top"><span class="rec-number">✓</span></div><h4>Ingen tydelige prioriterte tiltak</h4><p>Scoren er allerede svært høy. Se detaljene for eventuelle valgfrie forbedringer.</p></article>`;
  $('topRecommendations').querySelectorAll('[data-jump]').forEach(b=>b.addEventListener('click',()=>{const el=document.querySelector(`[data-check="${b.dataset.jump}"]`); if(el){el.classList.add('open');el.scrollIntoView({behavior:'smooth',block:'center'});}}));
}
function renderSummary(checks){const keys=['dmarc','spf','dkim','dnssec','dane'];$('summaryGrid').innerHTML=keys.map(k=>{const c=checks[k];return `<article class="summary-card"><div class="summary-top"><h4>${META[k][0]}</h4><span class="status-icon ${c.severity}">${ICON[c.severity]}</span></div><div class="summary-value">${esc(c.label)}</div><p>${esc(c.subtitle)}</p></article>`;}).join('');}
function renderBreakdown(checks){$('scoreBreakdown').innerHTML=Object.keys(WEIGHTS).map(k=>{const c=checks[k], e=earned(k,c), pct=Math.round(c.factor*100);return `<div class="score-row ${c.severity}"><div class="score-row-name"><strong>${esc(META[k][0])}</strong><span>${esc(META[k][1])}</span></div><div class="score-bar"><span style="width:${pct}%"></span></div><div class="score-points">${e}<span> / ${WEIGHTS[k]}</span></div></div>`;}).join('');}
function renderChecks(report){
  $('checksList').innerHTML=Object.keys(WEIGHTS).map(k=>{const c=report.checks[k], fix=fixData(k,c,report.domain), recs=(c.records||[]).map(r=>`<div class="record-box">${esc(r)}</div>`).join('');
    const fixHtml=fix?`<div class="fix-card"><div class="fix-card-head">Anbefalt tiltak</div><div class="fix-card-body"><ol>${fix.steps.map(s=>`<li>${esc(s)}</li>`).join('')}</ol>${fix.record?`<div class="fix-record"><dl class="fix-record-grid"><dt>Navn</dt><dd>${esc(fix.record.name)}</dd><dt>Type</dt><dd>${esc(fix.record.type)}</dd><dt>Verdi</dt><dd>${esc(fix.record.value)}</dd></dl></div>`:''}<p class="fix-warning">${esc(fix.warning)}</p></div></div>`:'';
    const limit=k==='certificate'?`<div class="limit-note">Denne GitHub Pages-versjonen kan bare bekrefte om nettleseren klarer en betrodd HTTPS-forbindelse. Den kan ikke hente sertifikatets utløpsdato eller inspisere SMTP STARTTLS uten en egen backend/API.</div>`:'';
    return `<article class="check-item" data-check="${k}"><button class="check-toggle" type="button"><span class="status-icon ${c.severity}">${ICON[c.severity]}</span><span class="check-name"><strong>${esc(META[k][0])}</strong><span>${esc(META[k][1])}</span></span><span class="check-status ${c.severity}">${esc(c.label)}</span><span class="chevron">⌄</span></button><div class="check-detail"><p><strong>${esc(c.subtitle)}</strong></p><p>${esc(c.detail)}</p>${recs}${limit}${fixHtml}</div></article>`;
  }).join('');
  $('checksList').querySelectorAll('.check-toggle').forEach(btn=>btn.addEventListener('click',()=>btn.closest('.check-item').classList.toggle('open')));
}
function renderAside(report){
  $('mxList').innerHTML=report.mxDetails.length?report.mxDetails.map(mx=>`<div class="mini-item"><strong>${esc(mx.host)}</strong><span>Prioritet ${mx.priority}</span><div class="mx-badges"><span class="mx-badge ${mx.aaaa.length?'good':'info'}">IPv6 ${mx.aaaa.length?'ja':'nei'}</span><span class="mx-badge ${mx.tlsa.length?'good':'info'}">TLSA ${mx.tlsa.length?'ja':'nei'}</span></div></div>`).join(''):'<div class="empty-mini">Ingen vanlige MX-servere funnet.</div>';
  const nss=answers(report.raw.ns,'NS').map(x=>cleanHost(x.data)), root4=answers(report.raw.a,'A').length, root6=answers(report.raw.aaaa,'AAAA').length;
  const providerNames=(report.providers||[]).map(p=>p.name), dkimMethod={'dns':'DNS-verifisert','provider-assurance':'Leverandørbekreftet','not-confirmed':'Ikke bekreftet','dns-error':'DNS-feil'}[report.checks.dkim.verificationMethod]||'Ukjent';
  $('dnsOverview').innerHTML=`<div><dt>Navneservere</dt><dd>${nss.length}</dd></div><div><dt>DNSSEC</dt><dd>${esc(report.checks.dnssec.label)}</dd></div><div><dt>IPv4 på domene</dt><dd>${root4?'Ja':'Nei'}</dd></div><div><dt>IPv6 på domene</dt><dd>${root6?'Ja':'Nei'}</dd></div><div><dt>MX-servere</dt><dd>${report.mxDetails.length}</dd></div><div><dt>DANE/TLSA</dt><dd>${esc(report.checks.dane.label)}</dd></div><div><dt>E-postleverandør</dt><dd>${esc(providerNames.length?providerNames.join(', '):'Ikke identifisert')}</dd></div><div><dt>DKIM-verifisering</dt><dd>${esc(dkimMethod)}</dd></div>`;
}

$('scanForm').addEventListener('submit',async e=>{
  e.preventDefault(); $('errorPanel').classList.add('hidden'); $('results').classList.add('hidden'); $('loading').classList.remove('hidden'); $('scanButton').disabled=true;
  try{const domain=normalizeDomain($('domainInput').value); const report=await scanDomain(domain,$('dkimSelector').value,$('scanCommonSelectors').checked); render(report);}
  catch(err){$('errorPanel').textContent=err?.message||'Kontrollen kunne ikke fullføres.';$('errorPanel').classList.remove('hidden');}
  finally{$('loading').classList.add('hidden');$('scanButton').disabled=false;}
});
$('expandAll').addEventListener('click',()=>{const items=[...document.querySelectorAll('.check-item')],all=items.every(x=>x.classList.contains('open'));items.forEach(x=>x.classList.toggle('open',!all));$('expandAll').textContent=all?'Vis alle':'Skjul alle';});
$('exportJson').addEventListener('click',()=>{if(!state.report)return;const blob=new Blob([JSON.stringify(state.report,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`mail-security-score-${state.report.domain}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);});
