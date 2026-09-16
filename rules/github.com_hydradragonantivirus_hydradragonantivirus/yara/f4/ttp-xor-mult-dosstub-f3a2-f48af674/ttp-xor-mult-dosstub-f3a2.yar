rule TTP_XOR_MULT_DOSStub_f3a2 {
  strings:
    $key_f3a2 = { a7 ca [2] d3 d2 [2] 94 d0 [2] d3 c1 [2] 9d cd [2] 91 c7 [2] 86 cc [2] 9d 82 [2] a0 }

  condition:
    any of them
}