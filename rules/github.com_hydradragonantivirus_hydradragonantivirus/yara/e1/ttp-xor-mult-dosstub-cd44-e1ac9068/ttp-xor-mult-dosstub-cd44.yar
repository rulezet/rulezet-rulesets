rule TTP_XOR_MULT_DOSStub_cd44 {
  strings:
    $key_cd44 = { 99 2c [2] ed 34 [2] aa 36 [2] ed 27 [2] a3 2b [2] af 21 [2] b8 2a [2] a3 64 [2] 9e }

  condition:
    any of them
}