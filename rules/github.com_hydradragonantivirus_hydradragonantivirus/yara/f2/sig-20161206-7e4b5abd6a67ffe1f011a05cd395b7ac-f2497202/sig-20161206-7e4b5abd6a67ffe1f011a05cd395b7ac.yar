rule sig_20161206_7e4b5abd6a67ffe1f011a05cd395b7ac {
  meta:
    description = "datamaliciousorder - file 20161206_7e4b5abd6a67ffe1f011a05cd395b7ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c7ef7283b7d15687e1b6e11399ce8fc4b4156991497a882f0ed7628d592f721"

  strings:
    $s1 = "var vBAo0 = new Function(\"s\", '{var vSz6 = new Date();vSz6[\"setUTCFullYear\"](\"2003\");if (vSz6.getUTCFullYear().toString(10" ascii
    $s2 = "var vBAo0 = new Function(\"s\", '{var vSz6 = new Date();vSz6[\"setUTCFullYear\"](\"2003\");if (vSz6.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vAv6 = s.split(\"##\"); return vAv6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vCc8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}