rule TTP_XOR_MULT_DOSStub_269a {
  strings:
    $key_269a = { 72 f2 [2] 06 ea [2] 41 e8 [2] 06 f9 [2] 48 f5 [2] 44 ff [2] 53 f4 [2] 48 ba [2] 75 }

  condition:
    any of them
}