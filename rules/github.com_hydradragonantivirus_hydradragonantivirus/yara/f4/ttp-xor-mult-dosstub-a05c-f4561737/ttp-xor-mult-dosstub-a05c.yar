rule TTP_XOR_MULT_DOSStub_a05c {
  strings:
    $key_a05c = { f4 34 [2] 80 2c [2] c7 2e [2] 80 3f [2] ce 33 [2] c2 39 [2] d5 32 [2] ce 7c [2] f3 }

  condition:
    any of them
}