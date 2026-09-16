rule TTP_XOR_MULT_DOSStub_2a71 {
  strings:
    $key_2a71 = { 7e 19 [2] 0a 01 [2] 4d 03 [2] 0a 12 [2] 44 1e [2] 48 14 [2] 5f 1f [2] 44 51 [2] 79 }

  condition:
    any of them
}