rule TTP_XOR_MULT_DOSStub_f7ba {
  strings:
    $key_f7ba = { a3 d2 [2] d7 ca [2] 90 c8 [2] d7 d9 [2] 99 d5 [2] 95 df [2] 82 d4 [2] 99 9a [2] a4 }

  condition:
    any of them
}