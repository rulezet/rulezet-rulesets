rule TTP_XOR_MULT_DOSStub_f350 {
  strings:
    $key_f350 = { a7 38 [2] d3 20 [2] 94 22 [2] d3 33 [2] 9d 3f [2] 91 35 [2] 86 3e [2] 9d 70 [2] a0 }

  condition:
    any of them
}