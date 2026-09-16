rule TTP_XOR_MULT_DOSStub_14fe {
  strings:
    $key_14fe = { 40 96 [2] 34 8e [2] 73 8c [2] 34 9d [2] 7a 91 [2] 76 9b [2] 61 90 [2] 7a de [2] 47 }

  condition:
    any of them
}