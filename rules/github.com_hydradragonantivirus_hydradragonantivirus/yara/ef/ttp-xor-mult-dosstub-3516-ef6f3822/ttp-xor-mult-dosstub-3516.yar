rule TTP_XOR_MULT_DOSStub_3516 {
  strings:
    $key_3516 = { 61 7e [2] 15 66 [2] 52 64 [2] 15 75 [2] 5b 79 [2] 57 73 [2] 40 78 [2] 5b 36 [2] 66 }

  condition:
    any of them
}