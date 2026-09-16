rule TTP_XOR_MULT_DOSStub_5197 {
  strings:
    $key_5197 = { 05 ff [2] 71 e7 [2] 36 e5 [2] 71 f4 [2] 3f f8 [2] 33 f2 [2] 24 f9 [2] 3f b7 [2] 02 }

  condition:
    any of them
}