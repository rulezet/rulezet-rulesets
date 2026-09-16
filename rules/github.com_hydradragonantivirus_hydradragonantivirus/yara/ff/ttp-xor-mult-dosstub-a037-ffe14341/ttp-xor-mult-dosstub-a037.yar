rule TTP_XOR_MULT_DOSStub_a037 {
  strings:
    $key_a037 = { f4 5f [2] 80 47 [2] c7 45 [2] 80 54 [2] ce 58 [2] c2 52 [2] d5 59 [2] ce 17 [2] f3 }

  condition:
    any of them
}