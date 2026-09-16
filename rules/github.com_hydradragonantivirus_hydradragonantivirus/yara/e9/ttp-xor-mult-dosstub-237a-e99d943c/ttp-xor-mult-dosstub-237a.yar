rule TTP_XOR_MULT_DOSStub_237a {
  strings:
    $key_237a = { 77 12 [2] 03 0a [2] 44 08 [2] 03 19 [2] 4d 15 [2] 41 1f [2] 56 14 [2] 4d 5a [2] 70 }

  condition:
    any of them
}