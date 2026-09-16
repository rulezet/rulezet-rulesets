rule sig_20161206_1e8918542a229dd3488e8b38249b262c {
  meta:
    description = "datamaliciousorder - file 20161206_1e8918542a229dd3488e8b38249b262c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a10ed5d6000939762940de2d5704155be334591ff61676fe8d4f929a1d798a28"

  strings:
    $s1 = "var vLm5 = new Function(\"s\", '{var vJMt6 = new Date();vJMt6[\"setUTCFullYear\"](\"2003\");if (vJMt6.getUTCFullYear().toString(" ascii
    $s2 = "var vLm5 = new Function(\"s\", '{var vJMt6 = new Date();vJMt6[\"setUTCFullYear\"](\"2003\");if (vJMt6.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vPMn8 = s.split(\"##\"); return vPMn8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vQRo5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}