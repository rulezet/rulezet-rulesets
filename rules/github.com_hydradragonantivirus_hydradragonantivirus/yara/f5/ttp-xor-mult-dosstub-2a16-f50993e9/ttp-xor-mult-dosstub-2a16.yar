rule TTP_XOR_MULT_DOSStub_2a16 {
  strings:
    $key_2a16 = { 7e 7e [2] 0a 66 [2] 4d 64 [2] 0a 75 [2] 44 79 [2] 48 73 [2] 5f 78 [2] 44 36 [2] 79 }

  condition:
    any of them
}