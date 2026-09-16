rule TTP_XOR_MULT_DOSStub_6b16 {
  strings:
    $key_6b16 = { 3f 7e [2] 4b 66 [2] 0c 64 [2] 4b 75 [2] 05 79 [2] 09 73 [2] 1e 78 [2] 05 36 [2] 38 }

  condition:
    any of them
}