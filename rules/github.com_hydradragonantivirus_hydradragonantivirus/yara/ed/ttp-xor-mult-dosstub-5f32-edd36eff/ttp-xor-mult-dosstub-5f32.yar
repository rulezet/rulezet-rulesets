rule TTP_XOR_MULT_DOSStub_5f32 {
  strings:
    $key_5f32 = { 0b 5a [2] 7f 42 [2] 38 40 [2] 7f 51 [2] 31 5d [2] 3d 57 [2] 2a 5c [2] 31 12 [2] 0c }

  condition:
    any of them
}