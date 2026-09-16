rule TTP_XOR_MULT_DOSStub_2b1d {
  strings:
    $key_2b1d = { 7f 75 [2] 0b 6d [2] 4c 6f [2] 0b 7e [2] 45 72 [2] 49 78 [2] 5e 73 [2] 45 3d [2] 78 }

  condition:
    any of them
}