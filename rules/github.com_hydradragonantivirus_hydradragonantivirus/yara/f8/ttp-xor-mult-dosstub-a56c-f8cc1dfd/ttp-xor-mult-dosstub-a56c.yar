rule TTP_XOR_MULT_DOSStub_a56c {
  strings:
    $key_a56c = { f1 04 [2] 85 1c [2] c2 1e [2] 85 0f [2] cb 03 [2] c7 09 [2] d0 02 [2] cb 4c [2] f6 }

  condition:
    any of them
}