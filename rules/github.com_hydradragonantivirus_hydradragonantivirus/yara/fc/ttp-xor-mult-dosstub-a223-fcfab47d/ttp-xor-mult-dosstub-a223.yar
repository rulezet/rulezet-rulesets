rule TTP_XOR_MULT_DOSStub_a223 {
  strings:
    $key_a223 = { f6 4b [2] 82 53 [2] c5 51 [2] 82 40 [2] cc 4c [2] c0 46 [2] d7 4d [2] cc 03 [2] f1 }

  condition:
    any of them
}