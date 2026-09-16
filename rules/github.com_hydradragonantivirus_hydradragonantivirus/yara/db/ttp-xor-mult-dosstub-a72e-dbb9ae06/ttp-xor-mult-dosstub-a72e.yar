rule TTP_XOR_MULT_DOSStub_a72e {
  strings:
    $key_a72e = { f3 46 [2] 87 5e [2] c0 5c [2] 87 4d [2] c9 41 [2] c5 4b [2] d2 40 [2] c9 0e [2] f4 }

  condition:
    any of them
}