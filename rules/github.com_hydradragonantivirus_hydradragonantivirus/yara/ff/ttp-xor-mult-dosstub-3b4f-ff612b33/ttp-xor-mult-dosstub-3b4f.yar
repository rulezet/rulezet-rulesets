rule TTP_XOR_MULT_DOSStub_3b4f {
  strings:
    $key_3b4f = { 6f 27 [2] 1b 3f [2] 5c 3d [2] 1b 2c [2] 55 20 [2] 59 2a [2] 4e 21 [2] 55 6f [2] 68 }

  condition:
    any of them
}