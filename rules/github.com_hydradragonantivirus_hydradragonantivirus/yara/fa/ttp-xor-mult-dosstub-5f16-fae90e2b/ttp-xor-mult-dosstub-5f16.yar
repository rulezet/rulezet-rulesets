rule TTP_XOR_MULT_DOSStub_5f16 {
  strings:
    $key_5f16 = { 0b 7e [2] 7f 66 [2] 38 64 [2] 7f 75 [2] 31 79 [2] 3d 73 [2] 2a 78 [2] 31 36 [2] 0c }

  condition:
    any of them
}