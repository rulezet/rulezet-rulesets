rule TTP_XOR_MULT_DOSStub_ecd9 {
  strings:
    $key_ecd9 = { b8 b1 [2] cc a9 [2] 8b ab [2] cc ba [2] 82 b6 [2] 8e bc [2] 99 b7 [2] 82 f9 [2] bf }

  condition:
    any of them
}