rule TTP_XOR_MULT_DOSStub_c462 {
  strings:
    $key_c462 = { 90 0a [2] e4 12 [2] a3 10 [2] e4 01 [2] aa 0d [2] a6 07 [2] b1 0c [2] aa 42 [2] 97 }

  condition:
    any of them
}