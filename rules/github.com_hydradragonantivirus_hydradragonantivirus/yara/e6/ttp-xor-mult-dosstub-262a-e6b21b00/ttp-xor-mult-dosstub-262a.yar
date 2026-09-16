rule TTP_XOR_MULT_DOSStub_262a {
  strings:
    $key_262a = { 72 42 [2] 06 5a [2] 41 58 [2] 06 49 [2] 48 45 [2] 44 4f [2] 53 44 [2] 48 0a [2] 75 }

  condition:
    any of them
}