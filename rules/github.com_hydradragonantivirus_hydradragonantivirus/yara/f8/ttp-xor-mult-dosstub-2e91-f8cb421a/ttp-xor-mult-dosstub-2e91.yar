rule TTP_XOR_MULT_DOSStub_2e91 {
  strings:
    $key_2e91 = { 7a f9 [2] 0e e1 [2] 49 e3 [2] 0e f2 [2] 40 fe [2] 4c f4 [2] 5b ff [2] 40 b1 [2] 7d }

  condition:
    any of them
}