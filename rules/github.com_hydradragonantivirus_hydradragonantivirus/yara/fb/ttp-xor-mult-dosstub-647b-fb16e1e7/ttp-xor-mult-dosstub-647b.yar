rule TTP_XOR_MULT_DOSStub_647b {
  strings:
    $key_647b = { 30 13 [2] 44 0b [2] 03 09 [2] 44 18 [2] 0a 14 [2] 06 1e [2] 11 15 [2] 0a 5b [2] 37 }

  condition:
    any of them
}