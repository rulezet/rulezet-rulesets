rule TTP_XOR_MULT_DOSStub_23fe {
  strings:
    $key_23fe = { 77 96 [2] 03 8e [2] 44 8c [2] 03 9d [2] 4d 91 [2] 41 9b [2] 56 90 [2] 4d de [2] 70 }

  condition:
    any of them
}