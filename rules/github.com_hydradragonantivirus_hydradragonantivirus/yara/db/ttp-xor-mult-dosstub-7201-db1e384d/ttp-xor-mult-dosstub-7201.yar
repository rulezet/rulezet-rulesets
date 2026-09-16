rule TTP_XOR_MULT_DOSStub_7201 {
  strings:
    $key_7201 = { 26 69 [2] 52 71 [2] 15 73 [2] 52 62 [2] 1c 6e [2] 10 64 [2] 07 6f [2] 1c 21 [2] 21 }

  condition:
    any of them
}