rule TTP_XOR_MULT_DOSStub_cde2 {
  strings:
    $key_cde2 = { 99 8a [2] ed 92 [2] aa 90 [2] ed 81 [2] a3 8d [2] af 87 [2] b8 8c [2] a3 c2 [2] 9e }

  condition:
    any of them
}