rule TTP_XOR_MULT_DOSStub_0e6d {
  strings:
    $key_0e6d = { 5a 05 [2] 2e 1d [2] 69 1f [2] 2e 0e [2] 60 02 [2] 6c 08 [2] 7b 03 [2] 60 4d [2] 5d }

  condition:
    any of them
}