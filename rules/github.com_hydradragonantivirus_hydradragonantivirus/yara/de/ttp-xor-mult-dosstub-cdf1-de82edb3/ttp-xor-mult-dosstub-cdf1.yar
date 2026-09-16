rule TTP_XOR_MULT_DOSStub_cdf1 {
  strings:
    $key_cdf1 = { 99 99 [2] ed 81 [2] aa 83 [2] ed 92 [2] a3 9e [2] af 94 [2] b8 9f [2] a3 d1 [2] 9e }

  condition:
    any of them
}