rule TTP_XOR_MULT_DOSStub_0157 {
  strings:
    $key_0157 = { 55 3f [2] 21 27 [2] 66 25 [2] 21 34 [2] 6f 38 [2] 63 32 [2] 74 39 [2] 6f 77 [2] 52 }

  condition:
    any of them
}