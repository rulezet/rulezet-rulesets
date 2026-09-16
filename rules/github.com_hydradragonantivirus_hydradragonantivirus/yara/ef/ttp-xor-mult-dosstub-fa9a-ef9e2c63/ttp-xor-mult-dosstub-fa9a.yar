rule TTP_XOR_MULT_DOSStub_fa9a {
  strings:
    $key_fa9a = { ae f2 [2] da ea [2] 9d e8 [2] da f9 [2] 94 f5 [2] 98 ff [2] 8f f4 [2] 94 ba [2] a9 }

  condition:
    any of them
}