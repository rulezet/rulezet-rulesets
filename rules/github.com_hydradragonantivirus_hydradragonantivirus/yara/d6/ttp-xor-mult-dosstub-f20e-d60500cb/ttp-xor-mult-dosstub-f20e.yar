rule TTP_XOR_MULT_DOSStub_f20e {
  strings:
    $key_f20e = { a6 66 [2] d2 7e [2] 95 7c [2] d2 6d [2] 9c 61 [2] 90 6b [2] 87 60 [2] 9c 2e [2] a1 }

  condition:
    any of them
}