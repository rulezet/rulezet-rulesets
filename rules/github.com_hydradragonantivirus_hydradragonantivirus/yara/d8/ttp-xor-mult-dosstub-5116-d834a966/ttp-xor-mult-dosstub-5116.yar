rule TTP_XOR_MULT_DOSStub_5116 {
  strings:
    $key_5116 = { 05 7e [2] 71 66 [2] 36 64 [2] 71 75 [2] 3f 79 [2] 33 73 [2] 24 78 [2] 3f 36 [2] 02 }

  condition:
    any of them
}