rule TTP_XOR_MULT_DOSStub_6391 {
  strings:
    $key_6391 = { 37 f9 [2] 43 e1 [2] 04 e3 [2] 43 f2 [2] 0d fe [2] 01 f4 [2] 16 ff [2] 0d b1 [2] 30 }

  condition:
    any of them
}