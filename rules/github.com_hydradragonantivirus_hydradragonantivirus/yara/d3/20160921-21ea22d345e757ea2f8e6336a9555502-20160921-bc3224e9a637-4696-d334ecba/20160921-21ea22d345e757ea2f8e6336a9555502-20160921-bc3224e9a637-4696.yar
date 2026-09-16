rule _20160921_21ea22d345e757ea2f8e6336a9555502_20160921_bc3224e9a637_4696 {
  meta:
    description = "datamaliciousorder - from files 20160921_21ea22d345e757ea2f8e6336a9555502.js, 20160921_bc3224e9a637b2113b3de820bcee66c0.js, 20160921_df47c7f57f308287ca344dcc34150b37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8743d09e1e870afab5e1ecd8d21f82873a9da6a025b74f14bc65477cea8f023"
    hash2       = "65d11827de99ef59cd2cc61d914e235dd2b16ac6b8f4f65f39b8a79dad86ed57"
    hash3       = "dbb4502419f8afb7a2d5fc4186a2c7922701956498b55deb8c27312672415d9c"

  strings:
    $s1 = "function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){r" ascii
    $s2 = "ck(){return \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo" ascii
    $s3 = "(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";" ascii
    $s4 = " fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"" ascii
    $s5 = " \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}