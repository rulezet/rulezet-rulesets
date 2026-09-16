rule TTP_XOR_MULT_DOSStub_f3aa {
  strings:
    $key_f3aa = { a7 c2 [2] d3 da [2] 94 d8 [2] d3 c9 [2] 9d c5 [2] 91 cf [2] 86 c4 [2] 9d 8a [2] a0 }

  condition:
    any of them
}