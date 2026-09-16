rule TTP_XOR_MULT_DOSStub_7751 {
  strings:
    $key_7751 = { 23 39 [2] 57 21 [2] 10 23 [2] 57 32 [2] 19 3e [2] 15 34 [2] 02 3f [2] 19 71 [2] 24 }

  condition:
    any of them
}