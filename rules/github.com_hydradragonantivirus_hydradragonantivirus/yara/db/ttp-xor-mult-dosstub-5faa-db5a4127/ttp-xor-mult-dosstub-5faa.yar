rule TTP_XOR_MULT_DOSStub_5faa {
  strings:
    $key_5faa = { 0b c2 [2] 7f da [2] 38 d8 [2] 7f c9 [2] 31 c5 [2] 3d cf [2] 2a c4 [2] 31 8a [2] 0c }

  condition:
    any of them
}