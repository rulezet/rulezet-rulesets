rule TTP_XOR_MULT_DOSStub_1e6d {
  strings:
    $key_1e6d = { 4a 05 [2] 3e 1d [2] 79 1f [2] 3e 0e [2] 70 02 [2] 7c 08 [2] 6b 03 [2] 70 4d [2] 4d }

  condition:
    any of them
}