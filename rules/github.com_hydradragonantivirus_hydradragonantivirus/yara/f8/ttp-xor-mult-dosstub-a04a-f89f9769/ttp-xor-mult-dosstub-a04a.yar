rule TTP_XOR_MULT_DOSStub_a04a {
  strings:
    $key_a04a = { f4 22 [2] 80 3a [2] c7 38 [2] 80 29 [2] ce 25 [2] c2 2f [2] d5 24 [2] ce 6a [2] f3 }

  condition:
    any of them
}