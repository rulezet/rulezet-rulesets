rule TTP_XOR_MULT_DOSStub_015d {
  strings:
    $key_015d = { 55 35 [2] 21 2d [2] 66 2f [2] 21 3e [2] 6f 32 [2] 63 38 [2] 74 33 [2] 6f 7d [2] 52 }

  condition:
    any of them
}