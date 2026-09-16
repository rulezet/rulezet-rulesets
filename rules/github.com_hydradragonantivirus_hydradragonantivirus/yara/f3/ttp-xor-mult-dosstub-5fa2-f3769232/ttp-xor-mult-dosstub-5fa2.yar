rule TTP_XOR_MULT_DOSStub_5fa2 {
  strings:
    $key_5fa2 = { 0b ca [2] 7f d2 [2] 38 d0 [2] 7f c1 [2] 31 cd [2] 3d c7 [2] 2a cc [2] 31 82 [2] 0c }

  condition:
    any of them
}