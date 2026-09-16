rule TTP_XOR_MULT_DOSStub_f5a2 {
  strings:
    $key_f5a2 = { a1 ca [2] d5 d2 [2] 92 d0 [2] d5 c1 [2] 9b cd [2] 97 c7 [2] 80 cc [2] 9b 82 [2] a6 }

  condition:
    any of them
}