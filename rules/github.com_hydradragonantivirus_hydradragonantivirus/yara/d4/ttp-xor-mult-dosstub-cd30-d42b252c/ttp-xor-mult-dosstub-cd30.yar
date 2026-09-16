rule TTP_XOR_MULT_DOSStub_cd30 {
  strings:
    $key_cd30 = { 99 58 [2] ed 40 [2] aa 42 [2] ed 53 [2] a3 5f [2] af 55 [2] b8 5e [2] a3 10 [2] 9e }

  condition:
    any of them
}