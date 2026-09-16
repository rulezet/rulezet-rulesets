rule TTP_XOR_MULT_DOSStub_a210 {
  strings:
    $key_a210 = { f6 78 [2] 82 60 [2] c5 62 [2] 82 73 [2] cc 7f [2] c0 75 [2] d7 7e [2] cc 30 [2] f1 }

  condition:
    any of them
}