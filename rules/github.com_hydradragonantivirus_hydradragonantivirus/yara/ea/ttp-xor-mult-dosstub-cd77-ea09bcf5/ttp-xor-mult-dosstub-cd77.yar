rule TTP_XOR_MULT_DOSStub_cd77 {
  strings:
    $key_cd77 = { 99 1f [2] ed 07 [2] aa 05 [2] ed 14 [2] a3 18 [2] af 12 [2] b8 19 [2] a3 57 [2] 9e }

  condition:
    any of them
}