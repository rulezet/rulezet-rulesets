rule TTP_XOR_MULT_DOSStub_cd00 {
  strings:
    $key_cd00 = { 99 68 [2] ed 70 [2] aa 72 [2] ed 63 [2] a3 6f [2] af 65 [2] b8 6e [2] a3 20 [2] 9e }

  condition:
    any of them
}