rule TTP_XOR_MULT_DOSStub_f69a {
  strings:
    $key_f69a = { a2 f2 [2] d6 ea [2] 91 e8 [2] d6 f9 [2] 98 f5 [2] 94 ff [2] 83 f4 [2] 98 ba [2] a5 }

  condition:
    any of them
}