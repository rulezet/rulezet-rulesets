rule TTP_XOR_MULT_DOSStub_2b4f {
  strings:
    $key_2b4f = { 7f 27 [2] 0b 3f [2] 4c 3d [2] 0b 2c [2] 45 20 [2] 49 2a [2] 5e 21 [2] 45 6f [2] 78 }

  condition:
    any of them
}