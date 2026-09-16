rule TTP_XOR_MULT_DOSStub_f0ec {
  strings:
    $key_f0ec = { a4 84 [2] d0 9c [2] 97 9e [2] d0 8f [2] 9e 83 [2] 92 89 [2] 85 82 [2] 9e cc [2] a3 }

  condition:
    any of them
}