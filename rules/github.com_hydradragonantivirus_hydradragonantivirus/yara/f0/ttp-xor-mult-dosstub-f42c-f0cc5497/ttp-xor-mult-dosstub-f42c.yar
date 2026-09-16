rule TTP_XOR_MULT_DOSStub_f42c {
  strings:
    $key_f42c = { a0 44 [2] d4 5c [2] 93 5e [2] d4 4f [2] 9a 43 [2] 96 49 [2] 81 42 [2] 9a 0c [2] a7 }

  condition:
    any of them
}