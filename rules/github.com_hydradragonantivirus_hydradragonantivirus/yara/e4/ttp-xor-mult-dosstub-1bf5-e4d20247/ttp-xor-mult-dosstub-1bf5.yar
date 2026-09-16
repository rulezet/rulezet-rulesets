rule TTP_XOR_MULT_DOSStub_1bf5 {
  strings:
    $key_1bf5 = { 4f 9d [2] 3b 85 [2] 7c 87 [2] 3b 96 [2] 75 9a [2] 79 90 [2] 6e 9b [2] 75 d5 [2] 48 }

  condition:
    any of them
}