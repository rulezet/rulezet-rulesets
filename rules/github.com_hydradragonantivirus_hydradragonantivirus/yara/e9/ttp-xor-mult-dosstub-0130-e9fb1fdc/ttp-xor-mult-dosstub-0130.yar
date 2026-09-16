rule TTP_XOR_MULT_DOSStub_0130 {
  strings:
    $key_0130 = { 55 58 [2] 21 40 [2] 66 42 [2] 21 53 [2] 6f 5f [2] 63 55 [2] 74 5e [2] 6f 10 [2] 52 }

  condition:
    any of them
}