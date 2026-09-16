rule TTP_XOR_MULT_DOSStub_792d {
  strings:
    $key_792d = { 2d 45 [2] 59 5d [2] 1e 5f [2] 59 4e [2] 17 42 [2] 1b 48 [2] 0c 43 [2] 17 0d [2] 2a }

  condition:
    any of them
}