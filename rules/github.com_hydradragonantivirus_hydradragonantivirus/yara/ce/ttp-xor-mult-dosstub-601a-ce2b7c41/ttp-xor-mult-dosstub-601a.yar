rule TTP_XOR_MULT_DOSStub_601a {
  strings:
    $key_601a = { 34 72 [2] 40 6a [2] 07 68 [2] 40 79 [2] 0e 75 [2] 02 7f [2] 15 74 [2] 0e 3a [2] 33 }

  condition:
    any of them
}