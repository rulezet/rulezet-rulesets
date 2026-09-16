rule TTP_XOR_MULT_DOSStub_f76b {
  strings:
    $key_f76b = { a3 03 [2] d7 1b [2] 90 19 [2] d7 08 [2] 99 04 [2] 95 0e [2] 82 05 [2] 99 4b [2] a4 }

  condition:
    any of them
}