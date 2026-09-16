rule TTP_XOR_MULT_DOSStub_1be8 {
  strings:
    $key_1be8 = { 4f 80 [2] 3b 98 [2] 7c 9a [2] 3b 8b [2] 75 87 [2] 79 8d [2] 6e 86 [2] 75 c8 [2] 48 }

  condition:
    any of them
}