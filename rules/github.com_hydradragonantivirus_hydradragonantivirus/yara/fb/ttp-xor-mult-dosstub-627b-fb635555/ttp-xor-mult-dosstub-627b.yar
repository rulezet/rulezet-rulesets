rule TTP_XOR_MULT_DOSStub_627b {
  strings:
    $key_627b = { 36 13 [2] 42 0b [2] 05 09 [2] 42 18 [2] 0c 14 [2] 00 1e [2] 17 15 [2] 0c 5b [2] 31 }

  condition:
    any of them
}