rule TTP_XOR_MULT_DOSStub_a4e3 {
  strings:
    $key_a4e3 = { f0 8b [2] 84 93 [2] c3 91 [2] 84 80 [2] ca 8c [2] c6 86 [2] d1 8d [2] ca c3 [2] f7 }

  condition:
    any of them
}