rule TTP_XOR_MULT_DOSStub_a02e {
  strings:
    $key_a02e = { f4 46 [2] 80 5e [2] c7 5c [2] 80 4d [2] ce 41 [2] c2 4b [2] d5 40 [2] ce 0e [2] f3 }

  condition:
    any of them
}