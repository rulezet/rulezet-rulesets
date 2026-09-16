rule TTP_XOR_MULT_DOSStub_0601 {
  strings:
    $key_0601 = { 52 69 [2] 26 71 [2] 61 73 [2] 26 62 [2] 68 6e [2] 64 64 [2] 73 6f [2] 68 21 [2] 55 }

  condition:
    any of them
}