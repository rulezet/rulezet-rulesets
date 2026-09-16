rule TTP_XOR_MULT_DOSStub_a2fe {
  strings:
    $key_a2fe = { f6 96 [2] 82 8e [2] c5 8c [2] 82 9d [2] cc 91 [2] c0 9b [2] d7 90 [2] cc de [2] f1 }

  condition:
    any of them
}