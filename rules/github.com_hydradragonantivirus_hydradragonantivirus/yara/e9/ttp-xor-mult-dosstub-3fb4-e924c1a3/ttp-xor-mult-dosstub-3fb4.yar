rule TTP_XOR_MULT_DOSStub_3fb4 {
  strings:
    $key_3fb4 = { 6b dc [2] 1f c4 [2] 58 c6 [2] 1f d7 [2] 51 db [2] 5d d1 [2] 4a da [2] 51 94 [2] 6c }

  condition:
    any of them
}