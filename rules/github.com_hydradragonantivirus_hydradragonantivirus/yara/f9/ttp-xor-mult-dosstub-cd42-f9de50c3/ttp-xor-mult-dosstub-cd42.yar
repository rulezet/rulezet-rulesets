rule TTP_XOR_MULT_DOSStub_cd42 {
  strings:
    $key_cd42 = { 99 2a [2] ed 32 [2] aa 30 [2] ed 21 [2] a3 2d [2] af 27 [2] b8 2c [2] a3 62 [2] 9e }

  condition:
    any of them
}