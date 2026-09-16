rule TTP_XOR_MULT_DOSStub_2570 {
  strings:
    $key_2570 = { 71 18 [2] 05 00 [2] 42 02 [2] 05 13 [2] 4b 1f [2] 47 15 [2] 50 1e [2] 4b 50 [2] 76 }

  condition:
    any of them
}