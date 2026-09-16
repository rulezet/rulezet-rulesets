rule sig_20160219_49cd4e1fb7678a82105bd4b0512ec88a {
  meta:
    description = "datamaliciousorder - file 20160219_49cd4e1fb7678a82105bd4b0512ec88a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a9939d6ed34453253103679123ab948c4bcf3e207a61917405cb5a1999bc51e"

  strings:
    $x1  = " autopilotOperate=eval(('visa', 'robot', 'sphere', 'numeration', 'formal', '\\u0074vacuum'.e()) + 'hi' + ('peak', '\\u0073relaxa" ascii
    $s2  = "n', '\\u006egeneration'.e()) + ''; function String.prototype.e(a) {return this.charAt(a);} reorganizeSum = new autopilotOperate(" ascii
    $s3  = "emission', 'zone', 'tariff', '\\u0074audience'.e()) + 'at' + ('passion', 'portion', 'realization', 'project', '\\u0065section'.e" ascii
    $s4  = "bandage', 'memorial', '\\u0048price-list'.e()) + 'T' + ('recommend', 'axiom', '\\u0054trilogy'.e()) + 'P'); illusionProvocation[" ascii
    $s5  = "tory', 'clan', 'double', 'mass', '\\u006fskeleton'.e()) + 'F' + ('separation', 'image', 'amorphous', 'mask', 'astronaut', 'proje" ascii
    $s6  = "gent', 'beach', 'packing', 'examine', 'hotel', '\\u0045aspect'.e()) + 'n' + ('revision', 'toxic', 'attestation', 'patent', 'aqua" ascii
    $s7  = "', 'report', 'state', '\\u006fcollection'.e()) + 'se'](); reorganizeSum [dogmaRefrigerator](cafeProduce); } catch (careerIcon) {" ascii
    $s8  = ") + ''] < ((546/26)-(8*2+1))) {this[('show', 'anonymous', 'machine', 'cancer', 'fortune', '\\u0057certificate'.e()) + 'Sc' + ('s" ascii
    $s9  = "situation', 'cardinal', 'boss', 'veto', '\\u002evibration'.e()) + 'sc' + ('absurd', '\\u0072protector'.e()) + ''; illusionProvoc" ascii
    $s10 = "n', '\\u0073machine'.e()) + 'e' + ('saturation', '\\u006ereflex'.e()) + 'd'](); while (illusionProvocation[('preventive', 'lord'" ascii
    $s11 = "; } catch (careerIcon) {}; " fullword ascii

  condition:
    uint16(0) == 0x6120 and
    1 of ($x*) and all of them
}