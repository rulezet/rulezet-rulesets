rule TTP_XOR_MULT_DOSStub_a07c {
  strings:
    $key_a07c = { f4 14 [2] 80 0c [2] c7 0e [2] 80 1f [2] ce 13 [2] c2 19 [2] d5 12 [2] ce 5c [2] f3 }

  condition:
    any of them
}