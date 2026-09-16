rule TTP_XOR_MULT_DOSStub_57fe {
  strings:
    $key_57fe = { 03 96 [2] 77 8e [2] 30 8c [2] 77 9d [2] 39 91 [2] 35 9b [2] 22 90 [2] 39 de [2] 04 }

  condition:
    any of them
}