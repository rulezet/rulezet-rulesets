rule TTP_XOR_MULT_DOSStub_cde6 {
  strings:
    $key_cde6 = { 99 8e [2] ed 96 [2] aa 94 [2] ed 85 [2] a3 89 [2] af 83 [2] b8 88 [2] a3 c6 [2] 9e }

  condition:
    any of them
}