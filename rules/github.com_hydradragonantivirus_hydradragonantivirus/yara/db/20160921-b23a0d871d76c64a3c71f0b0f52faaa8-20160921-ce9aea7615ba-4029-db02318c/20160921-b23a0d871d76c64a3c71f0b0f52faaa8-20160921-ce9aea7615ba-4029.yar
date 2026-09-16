rule _20160921_b23a0d871d76c64a3c71f0b0f52faaa8_20160921_ce9aea7615ba_4029 {
  meta:
    description = "datamaliciousorder - from files 20160921_b23a0d871d76c64a3c71f0b0f52faaa8.js, 20160921_ce9aea7615ba4a71719a9c0d7f838fc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02969139df11550b994530c0bcbc6d946b6e49105015e9475f5de3942d78e5a1"
    hash2       = "1dfc225800b3b802cbdd9312a3198f5eb4bbcdb06d5f9ffd026bb3fb4f5cf4e6"

  strings:
    $s1 = "turn \"XFd\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"LGo\";})()," ascii
    $s2 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){r" ascii
    $s3 = "fuck(){return \"Xw\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"LLv" ascii
    $s4 = ";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii
    $s5 = "ction fuck(){return \"USf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii
    $s6 = "n \"Yk\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}