rule TTP_XOR_MULT_DOSStub_f73b {
  strings:
    $key_f73b = { a3 53 [2] d7 4b [2] 90 49 [2] d7 58 [2] 99 54 [2] 95 5e [2] 82 55 [2] 99 1b [2] a4 }

  condition:
    any of them
}