rule TTP_XOR_MULT_DOSStub_043a {
  strings:
    $key_043a = { 50 52 [2] 24 4a [2] 63 48 [2] 24 59 [2] 6a 55 [2] 66 5f [2] 71 54 [2] 6a 1a [2] 57 }

  condition:
    any of them
}