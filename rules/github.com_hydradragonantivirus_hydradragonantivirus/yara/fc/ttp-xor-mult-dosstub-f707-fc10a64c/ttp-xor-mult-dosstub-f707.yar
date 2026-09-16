rule TTP_XOR_MULT_DOSStub_f707 {
  strings:
    $key_f707 = { a3 6f [2] d7 77 [2] 90 75 [2] d7 64 [2] 99 68 [2] 95 62 [2] 82 69 [2] 99 27 [2] a4 }

  condition:
    any of them
}