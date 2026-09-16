rule TTP_XOR_MULT_DOSStub_f51e {
  strings:
    $key_f51e = { a1 76 [2] d5 6e [2] 92 6c [2] d5 7d [2] 9b 71 [2] 97 7b [2] 80 70 [2] 9b 3e [2] a6 }

  condition:
    any of them
}