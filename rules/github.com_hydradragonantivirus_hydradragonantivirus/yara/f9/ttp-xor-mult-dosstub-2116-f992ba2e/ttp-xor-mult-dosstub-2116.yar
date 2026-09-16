rule TTP_XOR_MULT_DOSStub_2116 {
  strings:
    $key_2116 = { 75 7e [2] 01 66 [2] 46 64 [2] 01 75 [2] 4f 79 [2] 43 73 [2] 54 78 [2] 4f 36 [2] 72 }

  condition:
    any of them
}