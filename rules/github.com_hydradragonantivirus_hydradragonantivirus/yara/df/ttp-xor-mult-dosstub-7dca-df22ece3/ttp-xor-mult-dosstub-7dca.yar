rule TTP_XOR_MULT_DOSStub_7dca {
  strings:
    $key_7dca = { 29 a2 [2] 5d ba [2] 1a b8 [2] 5d a9 [2] 13 a5 [2] 1f af [2] 08 a4 [2] 13 ea [2] 2e }

  condition:
    any of them
}