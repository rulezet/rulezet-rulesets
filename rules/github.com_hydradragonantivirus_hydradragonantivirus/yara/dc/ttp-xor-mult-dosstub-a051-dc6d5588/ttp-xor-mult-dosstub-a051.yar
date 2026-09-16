rule TTP_XOR_MULT_DOSStub_a051 {
  strings:
    $key_a051 = { f4 39 [2] 80 21 [2] c7 23 [2] 80 32 [2] ce 3e [2] c2 34 [2] d5 3f [2] ce 71 [2] f3 }

  condition:
    any of them
}