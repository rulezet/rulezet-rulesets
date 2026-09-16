rule TTP_XOR_MULT_DOSStub_3f53 {
  strings:
    $key_3f53 = { 6b 3b [2] 1f 23 [2] 58 21 [2] 1f 30 [2] 51 3c [2] 5d 36 [2] 4a 3d [2] 51 73 [2] 6c }

  condition:
    any of them
}