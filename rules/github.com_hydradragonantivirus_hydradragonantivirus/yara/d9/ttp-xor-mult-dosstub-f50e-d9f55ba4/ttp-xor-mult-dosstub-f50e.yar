rule TTP_XOR_MULT_DOSStub_f50e {
  strings:
    $key_f50e = { a1 66 [2] d5 7e [2] 92 7c [2] d5 6d [2] 9b 61 [2] 97 6b [2] 80 60 [2] 9b 2e [2] a6 }

  condition:
    any of them
}