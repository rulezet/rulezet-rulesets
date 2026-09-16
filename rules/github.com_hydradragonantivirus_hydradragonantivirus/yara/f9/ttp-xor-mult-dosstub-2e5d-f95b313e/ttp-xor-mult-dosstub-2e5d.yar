rule TTP_XOR_MULT_DOSStub_2e5d {
  strings:
    $key_2e5d = { 7a 35 [2] 0e 2d [2] 49 2f [2] 0e 3e [2] 40 32 [2] 4c 38 [2] 5b 33 [2] 40 7d [2] 7d }

  condition:
    any of them
}