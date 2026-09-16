rule TTP_XOR_MULT_DOSStub_0107 {
  strings:
    $key_0107 = { 55 6f [2] 21 77 [2] 66 75 [2] 21 64 [2] 6f 68 [2] 63 62 [2] 74 69 [2] 6f 27 [2] 52 }

  condition:
    any of them
}