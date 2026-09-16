rule TTP_XOR_MULT_DOSStub_6a5d {
  strings:
    $key_6a5d = { 3e 35 [2] 4a 2d [2] 0d 2f [2] 4a 3e [2] 04 32 [2] 08 38 [2] 1f 33 [2] 04 7d [2] 39 }

  condition:
    any of them
}