rule TTP_XOR_MULT_DOSStub_f67b {
  strings:
    $key_f67b = { a2 13 [2] d6 0b [2] 91 09 [2] d6 18 [2] 98 14 [2] 94 1e [2] 83 15 [2] 98 5b [2] a5 }

  condition:
    any of them
}