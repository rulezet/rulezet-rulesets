rule TTP_XOR_MULT_DOSStub_cd36 {
  strings:
    $key_cd36 = { 99 5e [2] ed 46 [2] aa 44 [2] ed 55 [2] a3 59 [2] af 53 [2] b8 58 [2] a3 16 [2] 9e }

  condition:
    any of them
}