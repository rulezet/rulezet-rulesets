rule TTP_XOR_MULT_DOSStub_e4fe {
  strings:
    $key_e4fe = { b0 96 [2] c4 8e [2] 83 8c [2] c4 9d [2] 8a 91 [2] 86 9b [2] 91 90 [2] 8a de [2] b7 }

  condition:
    any of them
}