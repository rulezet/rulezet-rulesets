rule TTP_XOR_MULT_DOSStub_40fe {
  strings:
    $key_40fe = { 14 96 [2] 60 8e [2] 27 8c [2] 60 9d [2] 2e 91 [2] 22 9b [2] 35 90 [2] 2e de [2] 13 }

  condition:
    any of them
}