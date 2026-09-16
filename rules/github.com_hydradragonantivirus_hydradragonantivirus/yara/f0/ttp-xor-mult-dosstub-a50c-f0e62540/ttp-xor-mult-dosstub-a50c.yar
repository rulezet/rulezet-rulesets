rule TTP_XOR_MULT_DOSStub_a50c {
  strings:
    $key_a50c = { f1 64 [2] 85 7c [2] c2 7e [2] 85 6f [2] cb 63 [2] c7 69 [2] d0 62 [2] cb 2c [2] f6 }

  condition:
    any of them
}