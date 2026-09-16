rule TTP_XOR_MULT_DOSStub_186d {
  strings:
    $key_186d = { 4c 05 [2] 38 1d [2] 7f 1f [2] 38 0e [2] 76 02 [2] 7a 08 [2] 6d 03 [2] 76 4d [2] 4b }

  condition:
    any of them
}