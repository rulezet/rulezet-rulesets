rule _20160921_468b13a80ecc75cd21428202c521ca1d_20160921_8753c13c904d_5067 {
  meta:
    description = "datamaliciousorder - from files 20160921_468b13a80ecc75cd21428202c521ca1d.js, 20160921_8753c13c904d4c1e9e4a848591336ee8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9bb117286f85c2017d3323a8a9f5fd0957993945e9e05ef190746247fc90de3"
    hash2       = "57611d1ad2ff9881d73dbaf53bfa8657402affd956dea32b9fc2afae375ffb9f"

  strings:
    $s1 = "nction fuck(){return \"Zy\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s2 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"FJs\";})(),(function " ascii
    $s3 = "tion fuck(){return \"MUs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s4 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"YAv\";})(),(function " ascii
    $s5 = "tion fuck(){return \"Ar\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}