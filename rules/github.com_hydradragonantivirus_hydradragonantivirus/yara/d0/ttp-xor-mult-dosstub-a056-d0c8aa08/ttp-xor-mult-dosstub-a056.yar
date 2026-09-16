rule TTP_XOR_MULT_DOSStub_a056 {
  strings:
    $key_a056 = { f4 3e [2] 80 26 [2] c7 24 [2] 80 35 [2] ce 39 [2] c2 33 [2] d5 38 [2] ce 76 [2] f3 }

  condition:
    any of them
}