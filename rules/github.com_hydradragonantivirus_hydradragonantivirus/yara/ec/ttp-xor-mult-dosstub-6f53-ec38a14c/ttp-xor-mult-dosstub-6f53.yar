rule TTP_XOR_MULT_DOSStub_6f53 {
  strings:
    $key_6f53 = { 3b 3b [2] 4f 23 [2] 08 21 [2] 4f 30 [2] 01 3c [2] 0d 36 [2] 1a 3d [2] 01 73 [2] 3c }

  condition:
    any of them
}