rule TTP_XOR_MULT_DOSStub_f2a8 {
  strings:
    $key_f2a8 = { a6 c0 [2] d2 d8 [2] 95 da [2] d2 cb [2] 9c c7 [2] 90 cd [2] 87 c6 [2] 9c 88 [2] a1 }

  condition:
    any of them
}