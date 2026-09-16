rule TTP_XOR_MULT_DOSStub_5f1d {
  strings:
    $key_5f1d = { 0b 75 [2] 7f 6d [2] 38 6f [2] 7f 7e [2] 31 72 [2] 3d 78 [2] 2a 73 [2] 31 3d [2] 0c }

  condition:
    any of them
}