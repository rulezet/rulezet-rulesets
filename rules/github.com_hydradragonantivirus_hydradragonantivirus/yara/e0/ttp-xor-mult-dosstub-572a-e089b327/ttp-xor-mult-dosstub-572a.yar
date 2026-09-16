rule TTP_XOR_MULT_DOSStub_572a {
  strings:
    $key_572a = { 03 42 [2] 77 5a [2] 30 58 [2] 77 49 [2] 39 45 [2] 35 4f [2] 22 44 [2] 39 0a [2] 04 }

  condition:
    any of them
}