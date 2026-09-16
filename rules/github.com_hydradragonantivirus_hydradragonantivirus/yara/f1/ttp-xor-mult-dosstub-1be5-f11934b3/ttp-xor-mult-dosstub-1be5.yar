rule TTP_XOR_MULT_DOSStub_1be5 {
  strings:
    $key_1be5 = { 4f 8d [2] 3b 95 [2] 7c 97 [2] 3b 86 [2] 75 8a [2] 79 80 [2] 6e 8b [2] 75 c5 [2] 48 }

  condition:
    any of them
}