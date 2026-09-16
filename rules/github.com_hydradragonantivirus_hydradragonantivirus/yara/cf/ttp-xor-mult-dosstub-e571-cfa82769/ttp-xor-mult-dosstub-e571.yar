rule TTP_XOR_MULT_DOSStub_e571 {
  strings:
    $key_e571 = { b1 19 [2] c5 01 [2] 82 03 [2] c5 12 [2] 8b 1e [2] 87 14 [2] 90 1f [2] 8b 51 [2] b6 }

  condition:
    any of them
}