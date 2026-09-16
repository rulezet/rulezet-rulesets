rule TTP_XOR_MULT_DOSStub_f358 {
  strings:
    $key_f358 = { a7 30 [2] d3 28 [2] 94 2a [2] d3 3b [2] 9d 37 [2] 91 3d [2] 86 36 [2] 9d 78 [2] a0 }

  condition:
    any of them
}