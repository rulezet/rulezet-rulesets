rule TTP_XOR_MULT_DOSStub_f03e {
  strings:
    $key_f03e = { a4 56 [2] d0 4e [2] 97 4c [2] d0 5d [2] 9e 51 [2] 92 5b [2] 85 50 [2] 9e 1e [2] a3 }

  condition:
    any of them
}