rule TTP_XOR_MULT_DOSStub_b99c {
  strings:
    $key_b99c = { ed f4 [2] 99 ec [2] de ee [2] 99 ff [2] d7 f3 [2] db f9 [2] cc f2 [2] d7 bc [2] ea }

  condition:
    any of them
}