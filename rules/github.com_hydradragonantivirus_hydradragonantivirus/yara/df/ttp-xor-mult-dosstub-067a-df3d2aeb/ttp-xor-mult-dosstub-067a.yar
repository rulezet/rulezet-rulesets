rule TTP_XOR_MULT_DOSStub_067a {
  strings:
    $key_067a = { 52 12 [2] 26 0a [2] 61 08 [2] 26 19 [2] 68 15 [2] 64 1f [2] 73 14 [2] 68 5a [2] 55 }

  condition:
    any of them
}