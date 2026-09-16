rule TTP_XOR_MULT_DOSStub_cd40 {
  strings:
    $key_cd40 = { 99 28 [2] ed 30 [2] aa 32 [2] ed 23 [2] a3 2f [2] af 25 [2] b8 2e [2] a3 60 [2] 9e }

  condition:
    any of them
}