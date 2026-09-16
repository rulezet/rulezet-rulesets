rule TTP_XOR_MULT_DOSStub_452b {
  strings:
    $key_452b = { 11 43 [2] 65 5b [2] 22 59 [2] 65 48 [2] 2b 44 [2] 27 4e [2] 30 45 [2] 2b 0b [2] 16 }

  condition:
    any of them
}