rule TTP_XOR_MULT_DOSStub_f32e {
  strings:
    $key_f32e = { a7 46 [2] d3 5e [2] 94 5c [2] d3 4d [2] 9d 41 [2] 91 4b [2] 86 40 [2] 9d 0e [2] a0 }

  condition:
    any of them
}