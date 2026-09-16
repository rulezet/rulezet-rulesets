rule _20160921_26653257e0da59c861fc658d3bccdafd_20160921_3b7ec37cdbfa_3550 {
  meta:
    description = "datamaliciousorder - from files 20160921_26653257e0da59c861fc658d3bccdafd.js, 20160921_3b7ec37cdbfac434e32c8743c60228af.js, 20160921_6fabf8ef6df7ba14509fab6de95d721f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dff3cae9c135714cad3879ac1ef904841ec9264e3448106fbedd3b57ca11e97"
    hash2       = "86390741cf6e610c2e526db749631548b514c268decade5a5870edfebb141d4b"
    hash3       = "a6962383b3793edac58fef061128f9047afb39eaa645d3f7977a775ceeb02e56"

  strings:
    $s1 = "rn \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(fu" ascii
    $s2 = "eturn \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s3 = "n fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"U" ascii
    $s4 = "n fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s5 = ")(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function fuc" ascii
    $s6 = "uck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"US" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}