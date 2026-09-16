rule TTP_XOR_MULT_DOSStub_f4a2 {
  strings:
    $key_f4a2 = { a0 ca [2] d4 d2 [2] 93 d0 [2] d4 c1 [2] 9a cd [2] 96 c7 [2] 81 cc [2] 9a 82 [2] a7 }

  condition:
    any of them
}