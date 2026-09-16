rule TTP_XOR_MULT_DOSStub_f3b3 {
  strings:
    $key_f3b3 = { a7 db [2] d3 c3 [2] 94 c1 [2] d3 d0 [2] 9d dc [2] 91 d6 [2] 86 dd [2] 9d 93 [2] a0 }

  condition:
    any of them
}