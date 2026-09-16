rule sig_20170317_d46aac8fea73563ed94cea04f50ec2af {
  meta:
    description = "datamaliciousorder - file 20170317_d46aac8fea73563ed94cea04f50ec2af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdcbd2f8536e2f276a1e14108a521ce51b410b5297187d5225f9590668f07be7"

  strings:
    $s1  = "function cwbxnryerh(imycknmste)" fullword ascii
    $s2  = "return jrtanoeblb^mlmevbvmxw;" fullword ascii
    $s3  = "function movfxgubyx(jrtanoeblb,mlmevbvmxw){" fullword ascii
    $s4  = "function sfaqweaask()" fullword ascii
    $s5  = "return zgajevgfah[Math[\"floo\"+\"\"+\"r\"](Math.random()*zgajevgfah.length)];" fullword ascii
    $s6  = "vmvgdbafwx=(new Function(\"jrfwrgrfmh\",\"var ynatmlicxz=jrfwrgrfmh.match(/\\\\S{6}/g),xpfbricnog=\\\"\\\",nmkdqcwtpq=0;while(nm" ascii
    $s7  = "function zhmrzmcwxh()" fullword ascii
    $s8  = "vmvgdbafwx=(new Function(\"jrfwrgrfmh\",\"var ynatmlicxz=jrfwrgrfmh.match(/\\\\S{6}/g),xpfbricnog=\\\"\\\",nmkdqcwtpq=0;while(nm" ascii
    $s9  = "var zgajevgfah=new Array(\"d\",\"v\",\"e\",\"a\",\"l\",\"^\");" fullword ascii
    $s10 = "return parseInt(imycknmste.substr(4,2),16);" fullword ascii
    $s11 = "return irymcwizth;" fullword ascii
    $s12 = "function egfskzrjgl(bpxctlmpxe)" fullword ascii
    $s13 = "return vmvgdbafwx;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}