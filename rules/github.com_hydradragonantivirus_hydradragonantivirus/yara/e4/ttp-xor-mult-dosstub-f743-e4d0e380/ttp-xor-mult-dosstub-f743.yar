rule TTP_XOR_MULT_DOSStub_f743 {
  strings:
    $key_f743 = { a3 2b [2] d7 33 [2] 90 31 [2] d7 20 [2] 99 2c [2] 95 26 [2] 82 2d [2] 99 63 [2] a4 }

  condition:
    any of them
}