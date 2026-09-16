rule TTP_XOR_MULT_DOSStub_087b {
  strings:
    $key_087b = { 5c 13 [2] 28 0b [2] 6f 09 [2] 28 18 [2] 66 14 [2] 6a 1e [2] 7d 15 [2] 66 5b [2] 5b }

  condition:
    any of them
}