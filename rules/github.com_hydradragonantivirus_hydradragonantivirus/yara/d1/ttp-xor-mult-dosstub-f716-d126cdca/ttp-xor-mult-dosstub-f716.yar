rule TTP_XOR_MULT_DOSStub_f716 {
  strings:
    $key_f716 = { a3 7e [2] d7 66 [2] 90 64 [2] d7 75 [2] 99 79 [2] 95 73 [2] 82 78 [2] 99 36 [2] a4 }

  condition:
    any of them
}