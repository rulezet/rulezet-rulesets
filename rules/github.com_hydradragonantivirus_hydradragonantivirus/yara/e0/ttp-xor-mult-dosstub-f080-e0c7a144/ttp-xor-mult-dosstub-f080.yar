rule TTP_XOR_MULT_DOSStub_f080 {
  strings:
    $key_f080 = { a4 e8 [2] d0 f0 [2] 97 f2 [2] d0 e3 [2] 9e ef [2] 92 e5 [2] 85 ee [2] 9e a0 [2] a3 }

  condition:
    any of them
}