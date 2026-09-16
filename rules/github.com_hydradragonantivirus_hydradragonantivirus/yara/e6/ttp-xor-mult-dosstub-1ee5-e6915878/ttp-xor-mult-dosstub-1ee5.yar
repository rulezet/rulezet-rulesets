rule TTP_XOR_MULT_DOSStub_1ee5 {
  strings:
    $key_1ee5 = { 4a 8d [2] 3e 95 [2] 79 97 [2] 3e 86 [2] 70 8a [2] 7c 80 [2] 6b 8b [2] 70 c5 [2] 4d }

  condition:
    any of them
}