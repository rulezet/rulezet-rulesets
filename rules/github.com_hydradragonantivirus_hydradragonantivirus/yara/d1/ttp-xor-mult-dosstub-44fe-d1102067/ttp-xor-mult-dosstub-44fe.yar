rule TTP_XOR_MULT_DOSStub_44fe {
  strings:
    $key_44fe = { 10 96 [2] 64 8e [2] 23 8c [2] 64 9d [2] 2a 91 [2] 26 9b [2] 31 90 [2] 2a de [2] 17 }

  condition:
    any of them
}