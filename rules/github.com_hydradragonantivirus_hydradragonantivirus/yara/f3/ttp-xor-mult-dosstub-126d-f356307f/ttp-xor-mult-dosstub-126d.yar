rule TTP_XOR_MULT_DOSStub_126d {
  strings:
    $key_126d = { 46 05 [2] 32 1d [2] 75 1f [2] 32 0e [2] 7c 02 [2] 70 08 [2] 67 03 [2] 7c 4d [2] 41 }

  condition:
    any of them
}