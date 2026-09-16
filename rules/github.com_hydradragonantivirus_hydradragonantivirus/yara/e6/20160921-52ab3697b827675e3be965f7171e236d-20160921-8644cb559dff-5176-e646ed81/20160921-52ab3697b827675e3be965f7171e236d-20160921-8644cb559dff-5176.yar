rule _20160921_52ab3697b827675e3be965f7171e236d_20160921_8644cb559dff_5176 {
  meta:
    description = "datamaliciousorder - from files 20160921_52ab3697b827675e3be965f7171e236d.js, 20160921_8644cb559dff4747b398e56be3b4ea85.js, 20160921_b23a0d871d76c64a3c71f0b0f52faaa8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90a876a1d91ded80337b02adca1c227fdf5b5a96381a62397d3485e5e8ea108b"
    hash2       = "d92ab3635a987485347ef1a40e84d56adf54d5da5be50490856e0386b6ccabda"
    hash3       = "02969139df11550b994530c0bcbc6d946b6e49105015e9475f5de3942d78e5a1"

  strings:
    $s1 = ")(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s2 = "rn \"Yk\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s3 = "return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MIl\";})()" ascii
    $s4 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){ret" ascii
    $s5 = "s\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ar\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}