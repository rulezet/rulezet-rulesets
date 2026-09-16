rule TTP_XOR_MULT_DOSStub_f355 {
  strings:
    $key_f355 = { a7 3d [2] d3 25 [2] 94 27 [2] d3 36 [2] 9d 3a [2] 91 30 [2] 86 3b [2] 9d 75 [2] a0 }

  condition:
    any of them
}