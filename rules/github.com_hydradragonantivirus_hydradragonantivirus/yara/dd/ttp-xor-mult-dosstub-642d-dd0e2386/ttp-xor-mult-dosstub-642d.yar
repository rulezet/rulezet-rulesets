rule TTP_XOR_MULT_DOSStub_642d {
  strings:
    $key_642d = { 30 45 [2] 44 5d [2] 03 5f [2] 44 4e [2] 0a 42 [2] 06 48 [2] 11 43 [2] 0a 0d [2] 37 }

  condition:
    any of them
}