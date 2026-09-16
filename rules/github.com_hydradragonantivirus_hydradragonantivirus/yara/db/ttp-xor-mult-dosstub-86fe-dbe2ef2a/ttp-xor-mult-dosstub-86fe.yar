rule TTP_XOR_MULT_DOSStub_86fe {
  strings:
    $key_86fe = { d2 96 [2] a6 8e [2] e1 8c [2] a6 9d [2] e8 91 [2] e4 9b [2] f3 90 [2] e8 de [2] d5 }

  condition:
    any of them
}