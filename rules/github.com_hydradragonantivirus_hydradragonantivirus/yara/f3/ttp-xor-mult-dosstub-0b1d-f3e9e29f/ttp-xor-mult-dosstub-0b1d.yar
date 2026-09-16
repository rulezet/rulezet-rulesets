rule TTP_XOR_MULT_DOSStub_0b1d {
  strings:
    $key_0b1d = { 5f 75 [2] 2b 6d [2] 6c 6f [2] 2b 7e [2] 65 72 [2] 69 78 [2] 7e 73 [2] 65 3d [2] 58 }

  condition:
    any of them
}