rule _20160921_7cd473b59463126782b9a6cfaae72835_20160921_d1c97b87a698_5440 {
  meta:
    description = "datamaliciousorder - from files 20160921_7cd473b59463126782b9a6cfaae72835.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"
    hash2       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"

  strings:
    $s1 = ";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Yi\";})(),(function f00" ascii
    $s2 = ",(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Wb\";})(),(function f000(){r" ascii
    $s3 = "\"DYs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(funct" ascii
    $s4 = "\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Oh\";})(),(function f" ascii
    $s5 = "(function f000(){return \"Vj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}