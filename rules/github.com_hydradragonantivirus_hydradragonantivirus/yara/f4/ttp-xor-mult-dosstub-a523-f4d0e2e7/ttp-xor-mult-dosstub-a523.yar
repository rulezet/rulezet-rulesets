rule TTP_XOR_MULT_DOSStub_a523 {
  strings:
    $key_a523 = { f1 4b [2] 85 53 [2] c2 51 [2] 85 40 [2] cb 4c [2] c7 46 [2] d0 4d [2] cb 03 [2] f6 }

  condition:
    any of them
}