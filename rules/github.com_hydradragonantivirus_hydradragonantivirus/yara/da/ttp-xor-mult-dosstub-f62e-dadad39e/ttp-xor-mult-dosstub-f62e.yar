rule TTP_XOR_MULT_DOSStub_f62e {
  strings:
    $key_f62e = { a2 46 [2] d6 5e [2] 91 5c [2] d6 4d [2] 98 41 [2] 94 4b [2] 83 40 [2] 98 0e [2] a5 }

  condition:
    any of them
}