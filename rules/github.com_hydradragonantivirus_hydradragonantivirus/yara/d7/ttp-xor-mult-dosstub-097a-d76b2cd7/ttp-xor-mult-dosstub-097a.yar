rule TTP_XOR_MULT_DOSStub_097a {
  strings:
    $key_097a = { 5d 12 [2] 29 0a [2] 6e 08 [2] 29 19 [2] 67 15 [2] 6b 1f [2] 7c 14 [2] 67 5a [2] 5a }

  condition:
    any of them
}