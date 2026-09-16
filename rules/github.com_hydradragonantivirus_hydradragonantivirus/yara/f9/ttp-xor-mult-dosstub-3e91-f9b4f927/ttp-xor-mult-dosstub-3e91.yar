rule TTP_XOR_MULT_DOSStub_3e91 {
  strings:
    $key_3e91 = { 6a f9 [2] 1e e1 [2] 59 e3 [2] 1e f2 [2] 50 fe [2] 5c f4 [2] 4b ff [2] 50 b1 [2] 6d }

  condition:
    any of them
}