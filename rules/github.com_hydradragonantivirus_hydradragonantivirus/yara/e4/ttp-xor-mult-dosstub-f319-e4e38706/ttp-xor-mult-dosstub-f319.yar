rule TTP_XOR_MULT_DOSStub_f319 {
  strings:
    $key_f319 = { a7 71 [2] d3 69 [2] 94 6b [2] d3 7a [2] 9d 76 [2] 91 7c [2] 86 77 [2] 9d 39 [2] a0 }

  condition:
    any of them
}