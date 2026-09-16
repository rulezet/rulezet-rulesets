rule TTP_XOR_MULT_DOSStub_5f6d {
  strings:
    $key_5f6d = { 0b 05 [2] 7f 1d [2] 38 1f [2] 7f 0e [2] 31 02 [2] 3d 08 [2] 2a 03 [2] 31 4d [2] 0c }

  condition:
    any of them
}