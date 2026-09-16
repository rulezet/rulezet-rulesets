rule TTP_XOR_MULT_DOSStub_119a {
  strings:
    $key_119a = { 45 f2 [2] 31 ea [2] 76 e8 [2] 31 f9 [2] 7f f5 [2] 73 ff [2] 64 f4 [2] 7f ba [2] 42 }

  condition:
    any of them
}