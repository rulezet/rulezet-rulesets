rule TTP_XOR_MULT_DOSStub_3fa2 {
  strings:
    $key_3fa2 = { 6b ca [2] 1f d2 [2] 58 d0 [2] 1f c1 [2] 51 cd [2] 5d c7 [2] 4a cc [2] 51 82 [2] 6c }

  condition:
    any of them
}