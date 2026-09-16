rule TTP_XOR_MULT_DOSStub_5821 {
  strings:
    $key_5821 = { 0c 49 [2] 78 51 [2] 3f 53 [2] 78 42 [2] 36 4e [2] 3a 44 [2] 2d 4f [2] 36 01 [2] 0b }

  condition:
    any of them
}