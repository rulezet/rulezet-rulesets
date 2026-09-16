rule TTP_XOR_MULT_DOSStub_a021 {
  strings:
    $key_a021 = { f4 49 [2] 80 51 [2] c7 53 [2] 80 42 [2] ce 4e [2] c2 44 [2] d5 4f [2] ce 01 [2] f3 }

  condition:
    any of them
}