rule TTP_XOR_MULT_DOSStub_f473 {
  strings:
    $key_f473 = { a0 1b [2] d4 03 [2] 93 01 [2] d4 10 [2] 9a 1c [2] 96 16 [2] 81 1d [2] 9a 53 [2] a7 }

  condition:
    any of them
}