rule TTP_XOR_MULT_DOSStub_277a {
  strings:
    $key_277a = { 73 12 [2] 07 0a [2] 40 08 [2] 07 19 [2] 49 15 [2] 45 1f [2] 52 14 [2] 49 5a [2] 74 }

  condition:
    any of them
}