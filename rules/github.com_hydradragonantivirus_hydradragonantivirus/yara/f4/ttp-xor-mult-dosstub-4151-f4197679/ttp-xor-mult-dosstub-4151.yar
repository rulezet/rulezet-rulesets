rule TTP_XOR_MULT_DOSStub_4151 {
  strings:
    $key_4151 = { 15 39 [2] 61 21 [2] 26 23 [2] 61 32 [2] 2f 3e [2] 23 34 [2] 34 3f [2] 2f 71 [2] 12 }

  condition:
    any of them
}