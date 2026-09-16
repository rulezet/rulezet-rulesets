rule TTP_XOR_MULT_DOSStub_f1ee {
  strings:
    $key_f1ee = { a5 86 [2] d1 9e [2] 96 9c [2] d1 8d [2] 9f 81 [2] 93 8b [2] 84 80 [2] 9f ce [2] a2 }

  condition:
    any of them
}