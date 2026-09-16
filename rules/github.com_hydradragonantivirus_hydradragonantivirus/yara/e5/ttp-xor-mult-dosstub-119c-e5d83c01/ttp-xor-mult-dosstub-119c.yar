rule TTP_XOR_MULT_DOSStub_119c {
  strings:
    $key_119c = { 45 f4 [2] 31 ec [2] 76 ee [2] 31 ff [2] 7f f3 [2] 73 f9 [2] 64 f2 [2] 7f bc [2] 42 }

  condition:
    any of them
}