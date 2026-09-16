rule TTP_XOR_MULT_DOSStub_b0fe {
  strings:
    $key_b0fe = { e4 96 [2] 90 8e [2] d7 8c [2] 90 9d [2] de 91 [2] d2 9b [2] c5 90 [2] de de [2] e3 }

  condition:
    any of them
}