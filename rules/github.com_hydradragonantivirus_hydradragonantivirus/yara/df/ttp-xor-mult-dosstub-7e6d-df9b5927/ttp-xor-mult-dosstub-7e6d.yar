rule TTP_XOR_MULT_DOSStub_7e6d {
  strings:
    $key_7e6d = { 2a 05 [2] 5e 1d [2] 19 1f [2] 5e 0e [2] 10 02 [2] 1c 08 [2] 0b 03 [2] 10 4d [2] 2d }

  condition:
    any of them
}