rule TTP_XOR_MULT_DOSStub_a07d {
  strings:
    $key_a07d = { f4 15 [2] 80 0d [2] c7 0f [2] 80 1e [2] ce 12 [2] c2 18 [2] d5 13 [2] ce 5d [2] f3 }

  condition:
    any of them
}