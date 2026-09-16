rule TTP_XOR_MULT_DOSStub_f46b {
  strings:
    $key_f46b = { a0 03 [2] d4 1b [2] 93 19 [2] d4 08 [2] 9a 04 [2] 96 0e [2] 81 05 [2] 9a 4b [2] a7 }

  condition:
    any of them
}