rule TTP_XOR_MULT_DOSStub_7dfa {
  strings:
    $key_7dfa = { 29 92 [2] 5d 8a [2] 1a 88 [2] 5d 99 [2] 13 95 [2] 1f 9f [2] 08 94 [2] 13 da [2] 2e }

  condition:
    any of them
}