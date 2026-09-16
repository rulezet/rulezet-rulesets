rule TTP_XOR_MULT_DOSStub_a025 {
  strings:
    $key_a025 = { f4 4d [2] 80 55 [2] c7 57 [2] 80 46 [2] ce 4a [2] c2 40 [2] d5 4b [2] ce 05 [2] f3 }

  condition:
    any of them
}