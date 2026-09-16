rule TTP_XOR_MULT_DOSStub_0471 {
  strings:
    $key_0471 = { 50 19 [2] 24 01 [2] 63 03 [2] 24 12 [2] 6a 1e [2] 66 14 [2] 71 1f [2] 6a 51 [2] 57 }

  condition:
    any of them
}