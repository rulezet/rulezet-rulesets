rule sig_20161208_aca36cc4db1f5deb8739a47c5b7b8bfb {
  meta:
    description = "datamaliciousorder - file 20161208_aca36cc4db1f5deb8739a47c5b7b8bfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8af270e77061818a14fdf1df3d6fdec71dae89d5b4d1519d4df494cdf689fb16"

  strings:
    $s1 = "var vMBv2 = new Function(\"vMTw6\", '{return vMTw6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFy4 = new Function(\"vMT" ascii
    $s2 = "2 = new Date();vFDg2[\"setUTC\"+\"FullYear\"](\"2003\");if (vFDg2.getUTCFullYear().toString(10) == \"2003\") {var vUJy8 = vMTw6." ascii
    $s3 = "var vMBv2 = new Function(\"vMTw6\", '{return vMTw6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFy4 = new Function(\"vMT" ascii
    $s4 = "###\"); return vUJy8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}