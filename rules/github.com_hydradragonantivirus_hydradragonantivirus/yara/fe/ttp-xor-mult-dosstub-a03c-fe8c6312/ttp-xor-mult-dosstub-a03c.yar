rule TTP_XOR_MULT_DOSStub_a03c {
  strings:
    $key_a03c = { f4 54 [2] 80 4c [2] c7 4e [2] 80 5f [2] ce 53 [2] c2 59 [2] d5 52 [2] ce 1c [2] f3 }

  condition:
    any of them
}