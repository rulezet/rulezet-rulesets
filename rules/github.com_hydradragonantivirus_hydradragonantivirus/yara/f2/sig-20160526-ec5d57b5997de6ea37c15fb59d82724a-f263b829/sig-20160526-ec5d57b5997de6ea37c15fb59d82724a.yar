rule sig_20160526_ec5d57b5997de6ea37c15fb59d82724a {
  meta:
    description = "datamaliciousorder - file 20160526_ec5d57b5997de6ea37c15fb59d82724a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7698f83a54e2a7b545755738c80e9f00ece5b007fceb9c4fcbdd7c1999d256b7"

  strings:
    $s1 = "0mRQCXWA + c8fVPWZQI + )p3mESVTHI(m4sCQYZVX( = o5tHYBRWX rav\\n;\"323x\\\\11\" = p3mESVTHI rav\\n;\"313x\\\\\" = c8fVPWZQI rav" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}