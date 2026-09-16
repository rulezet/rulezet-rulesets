rule TTP_XOR_MULT_DOSStub_f5fc {
  strings:
    $key_f5fc = { a1 94 [2] d5 8c [2] 92 8e [2] d5 9f [2] 9b 93 [2] 97 99 [2] 80 92 [2] 9b dc [2] a6 }

  condition:
    any of them
}