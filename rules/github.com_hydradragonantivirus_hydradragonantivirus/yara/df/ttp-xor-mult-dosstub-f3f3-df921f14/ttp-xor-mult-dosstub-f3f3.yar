rule TTP_XOR_MULT_DOSStub_f3f3 {
  strings:
    $key_f3f3 = { a7 9b [2] d3 83 [2] 94 81 [2] d3 90 [2] 9d 9c [2] 91 96 [2] 86 9d [2] 9d d3 [2] a0 }

  condition:
    any of them
}