rule TTP_XOR_MULT_DOSStub_6dfa {
  strings:
    $key_6dfa = { 39 92 [2] 4d 8a [2] 0a 88 [2] 4d 99 [2] 03 95 [2] 0f 9f [2] 18 94 [2] 03 da [2] 3e }

  condition:
    any of them
}