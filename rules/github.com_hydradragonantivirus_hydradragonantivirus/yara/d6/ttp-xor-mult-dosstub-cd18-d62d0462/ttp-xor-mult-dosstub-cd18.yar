rule TTP_XOR_MULT_DOSStub_cd18 {
  strings:
    $key_cd18 = { 99 70 [2] ed 68 [2] aa 6a [2] ed 7b [2] a3 77 [2] af 7d [2] b8 76 [2] a3 38 [2] 9e }

  condition:
    any of them
}