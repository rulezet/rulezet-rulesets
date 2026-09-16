rule TTP_XOR_MULT_DOSStub_6b4f {
  strings:
    $key_6b4f = { 3f 27 [2] 4b 3f [2] 0c 3d [2] 4b 2c [2] 05 20 [2] 09 2a [2] 1e 21 [2] 05 6f [2] 38 }

  condition:
    any of them
}