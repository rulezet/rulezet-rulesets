rule TTP_XOR_MULT_DOSStub_b9ad {
  strings:
    $key_b9ad = { ed c5 [2] 99 dd [2] de df [2] 99 ce [2] d7 c2 [2] db c8 [2] cc c3 [2] d7 8d [2] ea }

  condition:
    any of them
}