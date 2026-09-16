rule TTP_XOR_MULT_DOSStub_f6e7 {
  strings:
    $key_f6e7 = { a2 8f [2] d6 97 [2] 91 95 [2] d6 84 [2] 98 88 [2] 94 82 [2] 83 89 [2] 98 c7 [2] a5 }

  condition:
    any of them
}