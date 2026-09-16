rule _20160921_125bc6e32001cf9e335a6ab52f464add_20160921_21ea22d345e7_4415 {
  meta:
    description = "datamaliciousorder - from files 20160921_125bc6e32001cf9e335a6ab52f464add.js, 20160921_21ea22d345e757ea2f8e6336a9555502.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85fd75eaf5744358778610f756047b2dcd2017e11bf6f105849c49d56486df9c"
    hash2       = "e8743d09e1e870afab5e1ecd8d21f82873a9da6a025b74f14bc65477cea8f023"

  strings:
    $s1 = "n fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s2 = "n\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MUs\";})(),(functio" ascii
    $s3 = "unction fuck(){return \"Ai\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retu" ascii
    $s4 = "){return \"Ik\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(" ascii
    $s5 = "n \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}