rule TTP_XOR_MULT_DOSStub_179c {
  strings:
    $key_179c = { 43 f4 [2] 37 ec [2] 70 ee [2] 37 ff [2] 79 f3 [2] 75 f9 [2] 62 f2 [2] 79 bc [2] 44 }

  condition:
    any of them
}