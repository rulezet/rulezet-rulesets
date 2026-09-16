rule TTP_XOR_MULT_DOSStub_559a {
  strings:
    $key_559a = { 01 f2 [2] 75 ea [2] 32 e8 [2] 75 f9 [2] 3b f5 [2] 37 ff [2] 20 f4 [2] 3b ba [2] 06 }

  condition:
    any of them
}