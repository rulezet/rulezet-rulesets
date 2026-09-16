rule TTP_XOR_MULT_DOSStub_f43b {
  strings:
    $key_f43b = { a0 53 [2] d4 4b [2] 93 49 [2] d4 58 [2] 9a 54 [2] 96 5e [2] 81 55 [2] 9a 1b [2] a7 }

  condition:
    any of them
}