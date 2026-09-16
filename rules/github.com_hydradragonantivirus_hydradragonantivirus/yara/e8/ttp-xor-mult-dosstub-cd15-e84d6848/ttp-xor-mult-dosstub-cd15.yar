rule TTP_XOR_MULT_DOSStub_cd15 {
  strings:
    $key_cd15 = { 99 7d [2] ed 65 [2] aa 67 [2] ed 76 [2] a3 7a [2] af 70 [2] b8 7b [2] a3 35 [2] 9e }

  condition:
    any of them
}