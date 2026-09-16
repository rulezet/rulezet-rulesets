rule TTP_XOR_MULT_DOSStub_2591 {
  strings:
    $key_2591 = { 71 f9 [2] 05 e1 [2] 42 e3 [2] 05 f2 [2] 4b fe [2] 47 f4 [2] 50 ff [2] 4b b1 [2] 76 }

  condition:
    any of them
}