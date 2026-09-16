rule TTP_XOR_MULT_DOSStub_6f32 {
  strings:
    $key_6f32 = { 3b 5a [2] 4f 42 [2] 08 40 [2] 4f 51 [2] 01 5d [2] 0d 57 [2] 1a 5c [2] 01 12 [2] 3c }

  condition:
    any of them
}