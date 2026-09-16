rule TTP_XOR_MULT_DOSStub_316d {
  strings:
    $key_316d = { 65 05 [2] 11 1d [2] 56 1f [2] 11 0e [2] 5f 02 [2] 53 08 [2] 44 03 [2] 5f 4d [2] 62 }

  condition:
    any of them
}