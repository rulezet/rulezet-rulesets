rule TTP_XOR_MULT_DOSStub_f308 {
  strings:
    $key_f308 = { a7 60 [2] d3 78 [2] 94 7a [2] d3 6b [2] 9d 67 [2] 91 6d [2] 86 66 [2] 9d 28 [2] a0 }

  condition:
    any of them
}