rule TTP_XOR_MULT_DOSStub_db9c {
  strings:
    $key_db9c = { 8f f4 [2] fb ec [2] bc ee [2] fb ff [2] b5 f3 [2] b9 f9 [2] ae f2 [2] b5 bc [2] 88 }

  condition:
    any of them
}