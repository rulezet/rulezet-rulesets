rule TTP_XOR_MULT_DOSStub_717a {
  strings:
    $key_717a = { 25 12 [2] 51 0a [2] 16 08 [2] 51 19 [2] 1f 15 [2] 13 1f [2] 04 14 [2] 1f 5a [2] 22 }

  condition:
    any of them
}