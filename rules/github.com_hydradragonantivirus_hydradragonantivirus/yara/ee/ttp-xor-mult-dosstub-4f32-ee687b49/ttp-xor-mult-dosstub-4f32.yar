rule TTP_XOR_MULT_DOSStub_4f32 {
  strings:
    $key_4f32 = { 1b 5a [2] 6f 42 [2] 28 40 [2] 6f 51 [2] 21 5d [2] 2d 57 [2] 3a 5c [2] 21 12 [2] 1c }

  condition:
    any of them
}