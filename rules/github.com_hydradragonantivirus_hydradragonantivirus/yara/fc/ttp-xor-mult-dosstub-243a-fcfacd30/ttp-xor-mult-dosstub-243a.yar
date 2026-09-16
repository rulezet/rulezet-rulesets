rule TTP_XOR_MULT_DOSStub_243a {
  strings:
    $key_243a = { 70 52 [2] 04 4a [2] 43 48 [2] 04 59 [2] 4a 55 [2] 46 5f [2] 51 54 [2] 4a 1a [2] 77 }

  condition:
    any of them
}