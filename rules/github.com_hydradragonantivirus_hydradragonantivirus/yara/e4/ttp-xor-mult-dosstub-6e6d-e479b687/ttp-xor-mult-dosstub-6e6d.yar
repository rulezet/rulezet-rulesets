rule TTP_XOR_MULT_DOSStub_6e6d {
  strings:
    $key_6e6d = { 3a 05 [2] 4e 1d [2] 09 1f [2] 4e 0e [2] 00 02 [2] 0c 08 [2] 1b 03 [2] 00 4d [2] 3d }

  condition:
    any of them
}