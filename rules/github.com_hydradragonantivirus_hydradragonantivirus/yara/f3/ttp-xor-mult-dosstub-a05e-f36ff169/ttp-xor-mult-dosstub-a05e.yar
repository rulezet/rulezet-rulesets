rule TTP_XOR_MULT_DOSStub_a05e {
  strings:
    $key_a05e = { f4 36 [2] 80 2e [2] c7 2c [2] 80 3d [2] ce 31 [2] c2 3b [2] d5 30 [2] ce 7e [2] f3 }

  condition:
    any of them
}