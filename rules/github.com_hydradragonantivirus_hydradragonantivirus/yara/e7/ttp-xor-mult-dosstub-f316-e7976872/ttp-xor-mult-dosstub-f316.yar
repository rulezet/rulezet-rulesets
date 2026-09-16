rule TTP_XOR_MULT_DOSStub_f316 {
  strings:
    $key_f316 = { a7 7e [2] d3 66 [2] 94 64 [2] d3 75 [2] 9d 79 [2] 91 73 [2] 86 78 [2] 9d 36 [2] a0 }

  condition:
    any of them
}