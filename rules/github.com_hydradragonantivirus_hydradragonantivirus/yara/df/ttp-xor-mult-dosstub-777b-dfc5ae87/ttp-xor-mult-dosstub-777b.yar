rule TTP_XOR_MULT_DOSStub_777b {
  strings:
    $key_777b = { 23 13 [2] 57 0b [2] 10 09 [2] 57 18 [2] 19 14 [2] 15 1e [2] 02 15 [2] 19 5b [2] 24 }

  condition:
    any of them
}