rule TTP_XOR_MULT_DOSStub_725d {
  strings:
    $key_725d = { 26 35 [2] 52 2d [2] 15 2f [2] 52 3e [2] 1c 32 [2] 10 38 [2] 07 33 [2] 1c 7d [2] 21 }

  condition:
    any of them
}