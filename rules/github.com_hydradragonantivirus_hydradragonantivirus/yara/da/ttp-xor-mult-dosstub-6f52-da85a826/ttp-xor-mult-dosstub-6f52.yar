rule TTP_XOR_MULT_DOSStub_6f52 {
  strings:
    $key_6f52 = { 3b 3a [2] 4f 22 [2] 08 20 [2] 4f 31 [2] 01 3d [2] 0d 37 [2] 1a 3c [2] 01 72 [2] 3c }

  condition:
    any of them
}