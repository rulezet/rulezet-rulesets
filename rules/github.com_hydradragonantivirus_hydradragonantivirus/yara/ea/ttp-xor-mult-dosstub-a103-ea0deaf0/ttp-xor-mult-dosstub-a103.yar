rule TTP_XOR_MULT_DOSStub_a103 {
  strings:
    $key_a103 = { f5 6b [2] 81 73 [2] c6 71 [2] 81 60 [2] cf 6c [2] c3 66 [2] d4 6d [2] cf 23 [2] f2 }

  condition:
    any of them
}