rule TTP_XOR_MULT_DOSStub_f7fe {
  strings:
    $key_f7fe = { a3 96 [2] d7 8e [2] 90 8c [2] d7 9d [2] 99 91 [2] 95 9b [2] 82 90 [2] 99 de [2] a4 }

  condition:
    any of them
}