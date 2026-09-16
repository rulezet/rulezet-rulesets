rule TTP_XOR_MULT_DOSStub_a7fe {
  strings:
    $key_a7fe = { f3 96 [2] 87 8e [2] c0 8c [2] 87 9d [2] c9 91 [2] c5 9b [2] d2 90 [2] c9 de [2] f4 }

  condition:
    any of them
}