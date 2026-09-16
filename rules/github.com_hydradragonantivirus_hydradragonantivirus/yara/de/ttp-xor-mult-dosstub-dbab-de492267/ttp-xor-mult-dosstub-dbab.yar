rule TTP_XOR_MULT_DOSStub_dbab {
  strings:
    $key_dbab = { 8f c3 [2] fb db [2] bc d9 [2] fb c8 [2] b5 c4 [2] b9 ce [2] ae c5 [2] b5 8b [2] 88 }

  condition:
    any of them
}