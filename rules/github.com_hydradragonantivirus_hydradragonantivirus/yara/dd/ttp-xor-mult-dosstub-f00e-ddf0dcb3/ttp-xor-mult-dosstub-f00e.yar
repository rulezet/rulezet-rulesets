rule TTP_XOR_MULT_DOSStub_f00e {
  strings:
    $key_f00e = { a4 66 [2] d0 7e [2] 97 7c [2] d0 6d [2] 9e 61 [2] 92 6b [2] 85 60 [2] 9e 2e [2] a3 }

  condition:
    any of them
}