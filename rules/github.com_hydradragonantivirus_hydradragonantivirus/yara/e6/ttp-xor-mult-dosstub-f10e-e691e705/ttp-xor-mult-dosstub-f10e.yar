rule TTP_XOR_MULT_DOSStub_f10e {
  strings:
    $key_f10e = { a5 66 [2] d1 7e [2] 96 7c [2] d1 6d [2] 9f 61 [2] 93 6b [2] 84 60 [2] 9f 2e [2] a2 }

  condition:
    any of them
}