rule TTP_XOR_MULT_DOSStub_f333 {
  strings:
    $key_f333 = { a7 5b [2] d3 43 [2] 94 41 [2] d3 50 [2] 9d 5c [2] 91 56 [2] 86 5d [2] 9d 13 [2] a0 }

  condition:
    any of them
}