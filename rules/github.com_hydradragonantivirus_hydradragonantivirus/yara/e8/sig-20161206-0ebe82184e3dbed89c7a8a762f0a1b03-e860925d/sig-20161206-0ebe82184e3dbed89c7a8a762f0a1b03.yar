rule sig_20161206_0ebe82184e3dbed89c7a8a762f0a1b03 {
  meta:
    description = "datamaliciousorder - file 20161206_0ebe82184e3dbed89c7a8a762f0a1b03.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2807566c03564d95fda3388cfc49bfd31f4a5f85754e5f63fdf71db245b0ddad"

  strings:
    $s1 = "var vNf1 = new Function(\"s\", '{var vBIp7 = new Date();vBIp7[\"setUTCFullYear\"](\"2003\");if (vBIp7.getUTCFullYear().toString(" ascii
    $s2 = "var vNf1 = new Function(\"s\", '{var vBIp7 = new Date();vBIp7[\"setUTCFullYear\"](\"2003\");if (vBIp7.getUTCFullYear().toString(" ascii
    $s3 = "function vDVn8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vMPm7 = s.split(\"##\"); return vMPm7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}