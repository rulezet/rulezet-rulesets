rule TTP_XOR_MULT_DOSStub_54fe {
  strings:
    $key_54fe = { 00 96 [2] 74 8e [2] 33 8c [2] 74 9d [2] 3a 91 [2] 36 9b [2] 21 90 [2] 3a de [2] 07 }

  condition:
    any of them
}