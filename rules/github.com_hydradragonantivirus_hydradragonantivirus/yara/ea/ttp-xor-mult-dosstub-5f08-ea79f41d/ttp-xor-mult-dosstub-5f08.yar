rule TTP_XOR_MULT_DOSStub_5f08 {
  strings:
    $key_5f08 = { 0b 60 [2] 7f 78 [2] 38 7a [2] 7f 6b [2] 31 67 [2] 3d 6d [2] 2a 66 [2] 31 28 [2] 0c }

  condition:
    any of them
}