rule TTP_XOR_MULT_DOSStub_984f {
  strings:
    $key_984f = { cc 27 [2] b8 3f [2] ff 3d [2] b8 2c [2] f6 20 [2] fa 2a [2] ed 21 [2] f6 6f [2] cb }

  condition:
    any of them
}