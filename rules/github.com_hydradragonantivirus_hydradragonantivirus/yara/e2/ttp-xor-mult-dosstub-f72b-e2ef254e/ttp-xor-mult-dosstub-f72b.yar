rule TTP_XOR_MULT_DOSStub_f72b {
  strings:
    $key_f72b = { a3 43 [2] d7 5b [2] 90 59 [2] d7 48 [2] 99 44 [2] 95 4e [2] 82 45 [2] 99 0b [2] a4 }

  condition:
    any of them
}