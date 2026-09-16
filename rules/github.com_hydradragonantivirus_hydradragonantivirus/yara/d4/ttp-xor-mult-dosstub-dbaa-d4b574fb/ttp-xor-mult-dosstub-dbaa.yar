rule TTP_XOR_MULT_DOSStub_dbaa {
  strings:
    $key_dbaa = { 8f c2 [2] fb da [2] bc d8 [2] fb c9 [2] b5 c5 [2] b9 cf [2] ae c4 [2] b5 8a [2] 88 }

  condition:
    any of them
}