rule TTP_XOR_MULT_DOSStub_a06e {
  strings:
    $key_a06e = { f4 06 [2] 80 1e [2] c7 1c [2] 80 0d [2] ce 01 [2] c2 0b [2] d5 00 [2] ce 4e [2] f3 }

  condition:
    any of them
}