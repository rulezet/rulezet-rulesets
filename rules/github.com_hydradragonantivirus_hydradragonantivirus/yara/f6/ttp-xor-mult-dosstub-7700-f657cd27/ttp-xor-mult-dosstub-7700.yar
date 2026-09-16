rule TTP_XOR_MULT_DOSStub_7700 {
  strings:
    $key_7700 = { 23 68 [2] 57 70 [2] 10 72 [2] 57 63 [2] 19 6f [2] 15 65 [2] 02 6e [2] 19 20 [2] 24 }

  condition:
    any of them
}