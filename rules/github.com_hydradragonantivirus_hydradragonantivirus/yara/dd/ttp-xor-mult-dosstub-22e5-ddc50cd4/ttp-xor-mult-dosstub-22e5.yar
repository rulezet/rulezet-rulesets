rule TTP_XOR_MULT_DOSStub_22e5 {
  strings:
    $key_22e5 = { 76 8d [2] 02 95 [2] 45 97 [2] 02 86 [2] 4c 8a [2] 40 80 [2] 57 8b [2] 4c c5 [2] 71 }

  condition:
    any of them
}