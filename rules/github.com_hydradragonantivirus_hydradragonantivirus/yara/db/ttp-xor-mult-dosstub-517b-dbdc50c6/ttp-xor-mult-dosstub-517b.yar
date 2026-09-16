rule TTP_XOR_MULT_DOSStub_517b {
  strings:
    $key_517b = { 05 13 [2] 71 0b [2] 36 09 [2] 71 18 [2] 3f 14 [2] 33 1e [2] 24 15 [2] 3f 5b [2] 02 }

  condition:
    any of them
}