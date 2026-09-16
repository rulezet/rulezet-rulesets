rule TTP_XOR_MULT_DOSStub_52fe {
  strings:
    $key_52fe = { 06 96 [2] 72 8e [2] 35 8c [2] 72 9d [2] 3c 91 [2] 30 9b [2] 27 90 [2] 3c de [2] 01 }

  condition:
    any of them
}