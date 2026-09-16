rule TTP_XOR_MULT_DOSStub_f3f7 {
  strings:
    $key_f3f7 = { a7 9f [2] d3 87 [2] 94 85 [2] d3 94 [2] 9d 98 [2] 91 92 [2] 86 99 [2] 9d d7 [2] a0 }

  condition:
    any of them
}