rule TTP_XOR_MULT_DOSStub_642a {
  strings:
    $key_642a = { 30 42 [2] 44 5a [2] 03 58 [2] 44 49 [2] 0a 45 [2] 06 4f [2] 11 44 [2] 0a 0a [2] 37 }

  condition:
    any of them
}