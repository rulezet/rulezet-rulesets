rule TTP_XOR_MULT_DOSStub_3b5d {
  strings:
    $key_3b5d = { 6f 35 [2] 1b 2d [2] 5c 2f [2] 1b 3e [2] 55 32 [2] 59 38 [2] 4e 33 [2] 55 7d [2] 68 }

  condition:
    any of them
}