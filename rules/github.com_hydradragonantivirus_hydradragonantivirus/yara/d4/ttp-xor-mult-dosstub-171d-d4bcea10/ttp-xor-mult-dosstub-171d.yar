rule TTP_XOR_MULT_DOSStub_171d {
  strings:
    $key_171d = { 43 75 [2] 37 6d [2] 70 6f [2] 37 7e [2] 79 72 [2] 75 78 [2] 62 73 [2] 79 3d [2] 44 }

  condition:
    any of them
}