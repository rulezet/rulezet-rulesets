rule TTP_XOR_MULT_DOSStub_f52e {
  strings:
    $key_f52e = { a1 46 [2] d5 5e [2] 92 5c [2] d5 4d [2] 9b 41 [2] 97 4b [2] 80 40 [2] 9b 0e [2] a6 }

  condition:
    any of them
}