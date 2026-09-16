rule TTP_XOR_MULT_DOSStub_066b {
  strings:
    $key_066b = { 52 03 [2] 26 1b [2] 61 19 [2] 26 08 [2] 68 04 [2] 64 0e [2] 73 05 [2] 68 4b [2] 55 }

  condition:
    any of them
}