rule TTP_XOR_MULT_DOSStub_565d {
  strings:
    $key_565d = { 02 35 [2] 76 2d [2] 31 2f [2] 76 3e [2] 38 32 [2] 34 38 [2] 23 33 [2] 38 7d [2] 05 }

  condition:
    any of them
}