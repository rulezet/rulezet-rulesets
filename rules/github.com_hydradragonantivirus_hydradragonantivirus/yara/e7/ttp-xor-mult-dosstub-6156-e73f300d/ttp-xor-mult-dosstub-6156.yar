rule TTP_XOR_MULT_DOSStub_6156 {
  strings:
    $key_6156 = { 35 3e [2] 41 26 [2] 06 24 [2] 41 35 [2] 0f 39 [2] 03 33 [2] 14 38 [2] 0f 76 [2] 32 }

  condition:
    any of them
}