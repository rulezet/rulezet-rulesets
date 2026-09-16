rule TTP_XOR_MULT_DOSStub_a575 {
  strings:
    $key_a575 = { f1 1d [2] 85 05 [2] c2 07 [2] 85 16 [2] cb 1a [2] c7 10 [2] d0 1b [2] cb 55 [2] f6 }

  condition:
    any of them
}