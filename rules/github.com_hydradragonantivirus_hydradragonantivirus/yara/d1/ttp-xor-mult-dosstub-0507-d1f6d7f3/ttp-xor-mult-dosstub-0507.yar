rule TTP_XOR_MULT_DOSStub_0507 {
  strings:
    $key_0507 = { 51 6f [2] 25 77 [2] 62 75 [2] 25 64 [2] 6b 68 [2] 67 62 [2] 70 69 [2] 6b 27 [2] 56 }

  condition:
    any of them
}