rule TTP_XOR_MULT_DOSStub_f67d {
  strings:
    $key_f67d = { a2 15 [2] d6 0d [2] 91 0f [2] d6 1e [2] 98 12 [2] 94 18 [2] 83 13 [2] 98 5d [2] a5 }

  condition:
    any of them
}