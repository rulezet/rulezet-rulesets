rule TTP_XOR_MULT_DOSStub_a53f {
  strings:
    $key_a53f = { f1 57 [2] 85 4f [2] c2 4d [2] 85 5c [2] cb 50 [2] c7 5a [2] d0 51 [2] cb 1f [2] f6 }

  condition:
    any of them
}