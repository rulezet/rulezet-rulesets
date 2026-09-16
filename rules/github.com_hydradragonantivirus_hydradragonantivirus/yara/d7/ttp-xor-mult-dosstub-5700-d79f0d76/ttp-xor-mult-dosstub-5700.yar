rule TTP_XOR_MULT_DOSStub_5700 {
  strings:
    $key_5700 = { 03 68 [2] 77 70 [2] 30 72 [2] 77 63 [2] 39 6f [2] 35 65 [2] 22 6e [2] 39 20 [2] 04 }

  condition:
    any of them
}