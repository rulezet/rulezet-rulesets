rule sig_20160219_a944129286fcc1595889b4b5e6e670ca {
  meta:
    description = "datamaliciousorder - file 20160219_a944129286fcc1595889b4b5e6e670ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea032f90ea2a5c43cece475b33fe7db3db6d1e81e8006a14ddb0a3ee658d611f"

  strings:
    $x1  = " tamponBureau=eval(('contract', 'provision', '\\u0074authority'.e()) + 'h' + ('diploma', 'camera', 'academy', 'bisexual', 'synon" ascii
    $s2  = "Ball [dictatorPeriod](registrationCommand); } catch (republicManuscript) {}; } catch (republicManuscript) {}; " fullword ascii
    $s3  = "axiom', 'chance', 'segment', '\\u0068skeleton'.e()) + 't' + ('meeting', 'agent', 'bomb', 'director', 'contact', 'veto', '\\u0074" ascii
    $s4  = "sion', 'transit', 'company', 'agent', '\\u002ecamera'.e()) + 'S' + ('delegation', 'caste', 'guard', 'saturation', '\\u0068chocol" ascii
    $s5  = "reservoir', 'firm', 'instrument', 'balloon', 'terror', '\\u004creflex'.e()) + 'HT' + ('raid', 'television', 'brilliant', '\\u005" ascii
    $s6  = "amine', 'catalogue', '\\u0050contact'.e()) + '%/') + \"3xseRQ0v\"+('formal', 'manifest', 'prospect', 'mass', '\\u002eapproximati" ascii
    $s7  = "\\u0052colony'.e()) + 'u' + ('barrier', 'theorem', 'saturation', 'medicine', '\\u006eacoustic'.e()) + ''; function String.protot" ascii
    $s8  = "n', 'impression', 'symphony', '\\u0074variation'.e()) + 'e'] < ((14-10)^(0+0))) {this[('block', 'discrete', '\\u0057massive'.e()" ascii
    $s9  = "ivilization', '\\u0063barrier'.e()) + 'lo' + ('prize', 'refrigerator', 'formal', 'absolute', '\\u0073incident'.e()) + 'e'](); ru" ascii
    $s10 = "delegation', 'false', 'delegation', '\\u0079sector'.e()) + '']); startStimulation[('extract', 'dictator', 'symphony', '\\u0070ba" ascii
    $s11 = "(); while (gramEssay[('conductor', 'sum', '\\u0072mark'.e()) + 'e' + ('mask', 'machine', '\\u0061ball'.e()) + 'd' + ('paragraph'" ascii
    $s12 = "e.e(a) {return this.charAt(a);} ruinBall = new tamponBureau(('classification', 'colony', 'music', 'presumption', '\\u0057delegat" ascii
    $s13 = "lation', 'cocoon', 'barrel', 'syndicate', '\\u006fhobby'.e()) + 'pe' + ('grammar', 'absolute', '\\u006erespectable'.e()) + '']()" ascii

  condition:
    uint16(0) == 0x7420 and
    1 of ($x*) and 4 of them
}