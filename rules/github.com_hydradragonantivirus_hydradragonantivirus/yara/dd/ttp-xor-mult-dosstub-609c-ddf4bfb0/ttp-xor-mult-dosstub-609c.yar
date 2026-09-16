rule TTP_XOR_MULT_DOSStub_609c {
  strings:
    $key_609c = { 34 f4 [2] 40 ec [2] 07 ee [2] 40 ff [2] 0e f3 [2] 02 f9 [2] 15 f2 [2] 0e bc [2] 33 }

  condition:
    any of them
}