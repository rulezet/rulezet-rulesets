rule TTP_XOR_MULT_DOSStub_5fe2 {
  strings:
    $key_5fe2 = { 0b 8a [2] 7f 92 [2] 38 90 [2] 7f 81 [2] 31 8d [2] 3d 87 [2] 2a 8c [2] 31 c2 [2] 0c }

  condition:
    any of them
}