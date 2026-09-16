rule TTP_XOR_MULT_DOSStub_727b {
  strings:
    $key_727b = { 26 13 [2] 52 0b [2] 15 09 [2] 52 18 [2] 1c 14 [2] 10 1e [2] 07 15 [2] 1c 5b [2] 21 }

  condition:
    any of them
}