rule TTP_XOR_MULT_DOSStub_f2fc {
  strings:
    $key_f2fc = { a6 94 [2] d2 8c [2] 95 8e [2] d2 9f [2] 9c 93 [2] 90 99 [2] 87 92 [2] 9c dc [2] a1 }

  condition:
    any of them
}