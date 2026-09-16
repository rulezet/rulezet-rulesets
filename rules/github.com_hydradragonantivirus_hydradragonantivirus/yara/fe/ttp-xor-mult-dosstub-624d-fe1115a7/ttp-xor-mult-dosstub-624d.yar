rule TTP_XOR_MULT_DOSStub_624d {
  strings:
    $key_624d = { 36 25 [2] 42 3d [2] 05 3f [2] 42 2e [2] 0c 22 [2] 00 28 [2] 17 23 [2] 0c 6d [2] 31 }

  condition:
    any of them
}