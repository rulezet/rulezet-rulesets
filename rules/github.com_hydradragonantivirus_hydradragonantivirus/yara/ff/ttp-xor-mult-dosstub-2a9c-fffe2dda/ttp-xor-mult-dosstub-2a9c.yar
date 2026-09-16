rule TTP_XOR_MULT_DOSStub_2a9c {
  strings:
    $key_2a9c = { 7e f4 [2] 0a ec [2] 4d ee [2] 0a ff [2] 44 f3 [2] 48 f9 [2] 5f f2 [2] 44 bc [2] 79 }

  condition:
    any of them
}