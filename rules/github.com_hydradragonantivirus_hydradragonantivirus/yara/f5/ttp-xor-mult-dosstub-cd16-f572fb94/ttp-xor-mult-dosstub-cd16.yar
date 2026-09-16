rule TTP_XOR_MULT_DOSStub_cd16 {
  strings:
    $key_cd16 = { 99 7e [2] ed 66 [2] aa 64 [2] ed 75 [2] a3 79 [2] af 73 [2] b8 78 [2] a3 36 [2] 9e }

  condition:
    any of them
}