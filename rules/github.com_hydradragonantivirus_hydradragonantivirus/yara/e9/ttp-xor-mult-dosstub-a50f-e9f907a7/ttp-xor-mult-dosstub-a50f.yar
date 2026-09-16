rule TTP_XOR_MULT_DOSStub_a50f {
  strings:
    $key_a50f = { f1 67 [2] 85 7f [2] c2 7d [2] 85 6c [2] cb 60 [2] c7 6a [2] d0 61 [2] cb 2f [2] f6 }

  condition:
    any of them
}