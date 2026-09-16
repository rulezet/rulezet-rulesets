rule TTP_XOR_MULT_DOSStub_f15c {
  strings:
    $key_f15c = { a5 34 [2] d1 2c [2] 96 2e [2] d1 3f [2] 9f 33 [2] 93 39 [2] 84 32 [2] 9f 7c [2] a2 }

  condition:
    any of them
}