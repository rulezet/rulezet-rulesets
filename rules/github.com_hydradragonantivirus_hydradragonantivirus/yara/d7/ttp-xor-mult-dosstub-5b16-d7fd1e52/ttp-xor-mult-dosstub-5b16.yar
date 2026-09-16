rule TTP_XOR_MULT_DOSStub_5b16 {
  strings:
    $key_5b16 = { 0f 7e [2] 7b 66 [2] 3c 64 [2] 7b 75 [2] 35 79 [2] 39 73 [2] 2e 78 [2] 35 36 [2] 08 }

  condition:
    any of them
}