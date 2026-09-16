rule TTP_XOR_MULT_DOSStub_2500 {
  strings:
    $key_2500 = { 71 68 [2] 05 70 [2] 42 72 [2] 05 63 [2] 4b 6f [2] 47 65 [2] 50 6e [2] 4b 20 [2] 76 }

  condition:
    any of them
}