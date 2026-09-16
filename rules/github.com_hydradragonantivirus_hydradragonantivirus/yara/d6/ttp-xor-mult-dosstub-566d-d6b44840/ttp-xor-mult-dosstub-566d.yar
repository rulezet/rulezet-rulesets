rule TTP_XOR_MULT_DOSStub_566d {
  strings:
    $key_566d = { 02 05 [2] 76 1d [2] 31 1f [2] 76 0e [2] 38 02 [2] 34 08 [2] 23 03 [2] 38 4d [2] 05 }

  condition:
    any of them
}