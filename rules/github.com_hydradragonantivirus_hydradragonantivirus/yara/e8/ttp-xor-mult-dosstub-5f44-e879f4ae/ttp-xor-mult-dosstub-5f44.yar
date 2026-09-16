rule TTP_XOR_MULT_DOSStub_5f44 {
  strings:
    $key_5f44 = { 0b 2c [2] 7f 34 [2] 38 36 [2] 7f 27 [2] 31 2b [2] 3d 21 [2] 2a 2a [2] 31 64 [2] 0c }

  condition:
    any of them
}