rule TTP_XOR_MULT_DOSStub_3b16 {
  strings:
    $key_3b16 = { 6f 7e [2] 1b 66 [2] 5c 64 [2] 1b 75 [2] 55 79 [2] 59 73 [2] 4e 78 [2] 55 36 [2] 68 }

  condition:
    any of them
}