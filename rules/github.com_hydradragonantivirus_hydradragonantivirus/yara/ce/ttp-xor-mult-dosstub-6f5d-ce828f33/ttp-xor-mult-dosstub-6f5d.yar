rule TTP_XOR_MULT_DOSStub_6f5d {
  strings:
    $key_6f5d = { 3b 35 [2] 4f 2d [2] 08 2f [2] 4f 3e [2] 01 32 [2] 0d 38 [2] 1a 33 [2] 01 7d [2] 3c }

  condition:
    any of them
}