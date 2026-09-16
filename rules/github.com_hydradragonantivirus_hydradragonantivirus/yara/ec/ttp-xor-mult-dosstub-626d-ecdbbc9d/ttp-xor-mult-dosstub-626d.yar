rule TTP_XOR_MULT_DOSStub_626d {
  strings:
    $key_626d = { 36 05 [2] 42 1d [2] 05 1f [2] 42 0e [2] 0c 02 [2] 00 08 [2] 17 03 [2] 0c 4d [2] 31 }

  condition:
    any of them
}