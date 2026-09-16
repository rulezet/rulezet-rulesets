rule TTP_XOR_MULT_DOSStub_057b {
  strings:
    $key_057b = { 51 13 [2] 25 0b [2] 62 09 [2] 25 18 [2] 6b 14 [2] 67 1e [2] 70 15 [2] 6b 5b [2] 56 }

  condition:
    any of them
}