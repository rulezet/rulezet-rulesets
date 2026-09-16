rule sig_20170126_5505cc98fd92a1d907cacda0209046c2 {
  meta:
    description = "datamaliciousorder - file 20170126_5505cc98fd92a1d907cacda0209046c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba6c4cfeb797600c2872cd7119c3c5943e876c8b9cdf98178b8b875aac756d7a"

  strings:
    $s1 = "//if ([\"yzqaz\", \"eloxyzk\", \"jquxofso\", new Function([\"lbitojwe\", \"zunyvy\", \"viqeg\", \"owafzyxk\", \"mquniqgi\", \"gc" ascii
    $s2 = "onzyholvu4 = this[[\"hkojwi\", \"gysy\", \"amocju\", \"oqqafu\", \"ewjysqo\", \"unep\", \"rihduh\", \"secetv\", \"kgigzeb\", \"g" ascii
    $s3 = "//if ([\"yzqaz\", \"eloxyzk\", \"jquxofso\", new Function([\"lbitojwe\", \"zunyvy\", \"viqeg\", \"owafzyxk\", \"mquniqgi\", \"gc" ascii
    $s4 = "onzyholvu4 = this[[\"hkojwi\", \"gysy\", \"amocju\", \"oqqafu\", \"ewjysqo\", \"unep\", \"rihduh\", \"secetv\", \"kgigzeb\", \"g" ascii

  condition:
    uint16(0) == 0x2f2f and
    all of them
}