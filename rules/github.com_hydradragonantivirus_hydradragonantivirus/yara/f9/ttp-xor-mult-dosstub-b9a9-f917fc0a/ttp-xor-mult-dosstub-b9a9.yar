rule TTP_XOR_MULT_DOSStub_b9a9 {
  strings:
    $key_b9a9 = { ed c1 [2] 99 d9 [2] de db [2] 99 ca [2] d7 c6 [2] db cc [2] cc c7 [2] d7 89 [2] ea }

  condition:
    any of them
}