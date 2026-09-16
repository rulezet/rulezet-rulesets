rule sig_20170215_f43d1f97ead6535e3f641d383d7f3af5 {
  meta:
    description = "datamaliciousorder - file 20170215_f43d1f97ead6535e3f641d383d7f3af5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb42ff2308b8605742a23aeaa1de752b422ac3cd5ac4a08682767a0283f0650c"

  strings:
    $s1 = "var z9 = \"http://\"; var x = new Array(\"azlivesound.com\", \"rancourtjobflow.net\", \"westlife.acapmichigan.com\", \"kristenda" ascii
    $s2 = "var z9 = \"http://\"; var x = new Array(\"azlivesound.com\", \"rancourtjobflow.net\", \"westlife.acapmichigan.com\", \"kristenda" ascii
    $s3 = "dokeJSpUJYnxlF5pUkxhNGOiUcMgL2CBhXA0\"; e.open(z7, x[i]+m, false); e.send(); var z3 = e.responseText; if (z3.length > 1000 && z3" ascii
    $s4 = "indexOf(m) > -1) { var z3 = z3.split(m).join(z4); eval(z3); break; }; } catch(e) { }; };" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}