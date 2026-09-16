rule TTP_XOR_MULT_DOSStub_0a4f {
  strings:
    $key_0a4f = { 5e 27 [2] 2a 3f [2] 6d 3d [2] 2a 2c [2] 64 20 [2] 68 2a [2] 7f 21 [2] 64 6f [2] 59 }

  condition:
    any of them
}