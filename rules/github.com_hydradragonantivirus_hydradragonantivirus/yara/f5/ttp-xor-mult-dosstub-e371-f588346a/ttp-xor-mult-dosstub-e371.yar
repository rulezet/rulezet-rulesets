rule TTP_XOR_MULT_DOSStub_e371 {
  strings:
    $key_e371 = { b7 19 [2] c3 01 [2] 84 03 [2] c3 12 [2] 8d 1e [2] 81 14 [2] 96 1f [2] 8d 51 [2] b0 }

  condition:
    any of them
}