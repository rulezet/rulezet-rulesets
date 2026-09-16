rule TTP_XOR_MULT_DOSStub_a0ec {
  strings:
    $key_a0ec = { f4 84 [2] 80 9c [2] c7 9e [2] 80 8f [2] ce 83 [2] c2 89 [2] d5 82 [2] ce cc [2] f3 }

  condition:
    any of them
}