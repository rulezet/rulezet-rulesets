rule TTP_XOR_MULT_DOSStub_eb4f {
  strings:
    $key_eb4f = { bf 27 [2] cb 3f [2] 8c 3d [2] cb 2c [2] 85 20 [2] 89 2a [2] 9e 21 [2] 85 6f [2] b8 }

  condition:
    any of them
}