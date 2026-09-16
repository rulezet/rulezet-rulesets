rule TTP_XOR_MULT_DOSStub_63fe {
  strings:
    $key_63fe = { 37 96 [2] 43 8e [2] 04 8c [2] 43 9d [2] 0d 91 [2] 01 9b [2] 16 90 [2] 0d de [2] 30 }

  condition:
    any of them
}