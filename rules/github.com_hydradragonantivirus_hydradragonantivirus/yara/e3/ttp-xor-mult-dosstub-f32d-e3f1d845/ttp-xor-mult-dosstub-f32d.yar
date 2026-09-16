rule TTP_XOR_MULT_DOSStub_f32d {
  strings:
    $key_f32d = { a7 45 [2] d3 5d [2] 94 5f [2] d3 4e [2] 9d 42 [2] 91 48 [2] 86 43 [2] 9d 0d [2] a0 }

  condition:
    any of them
}