rule TTP_XOR_MULT_DOSStub_5201 {
  strings:
    $key_5201 = { 06 69 [2] 72 71 [2] 35 73 [2] 72 62 [2] 3c 6e [2] 30 64 [2] 27 6f [2] 3c 21 [2] 01 }

  condition:
    any of them
}