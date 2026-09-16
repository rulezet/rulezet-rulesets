rule TTP_XOR_MULT_DOSStub_a00a {
  strings:
    $key_a00a = { f4 62 [2] 80 7a [2] c7 78 [2] 80 69 [2] ce 65 [2] c2 6f [2] d5 64 [2] ce 2a [2] f3 }

  condition:
    any of them
}