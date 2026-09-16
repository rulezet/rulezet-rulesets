rule TTP_XOR_MULT_DOSStub_a55e {
  strings:
    $key_a55e = { f1 36 [2] 85 2e [2] c2 2c [2] 85 3d [2] cb 31 [2] c7 3b [2] d0 30 [2] cb 7e [2] f6 }

  condition:
    any of them
}