rule TTP_XOR_MULT_DOSStub_636d {
  strings:
    $key_636d = { 37 05 [2] 43 1d [2] 04 1f [2] 43 0e [2] 0d 02 [2] 01 08 [2] 16 03 [2] 0d 4d [2] 30 }

  condition:
    any of them
}