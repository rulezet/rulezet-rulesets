rule TTP_XOR_MULT_DOSStub_e54f {
  strings:
    $key_e54f = { b1 27 [2] c5 3f [2] 82 3d [2] c5 2c [2] 8b 20 [2] 87 2a [2] 90 21 [2] 8b 6f [2] b6 }

  condition:
    any of them
}