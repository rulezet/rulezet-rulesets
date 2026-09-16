rule TTP_XOR_MULT_DOSStub_a073 {
  strings:
    $key_a073 = { f4 1b [2] 80 03 [2] c7 01 [2] 80 10 [2] ce 1c [2] c2 16 [2] d5 1d [2] ce 53 [2] f3 }

  condition:
    any of them
}