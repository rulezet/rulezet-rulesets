rule TTP_XOR_MULT_DOSStub_227c {
  strings:
    $key_227c = { 76 14 [2] 02 0c [2] 45 0e [2] 02 1f [2] 4c 13 [2] 40 19 [2] 57 12 [2] 4c 5c [2] 71 }

  condition:
    any of them
}