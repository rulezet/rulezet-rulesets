rule TTP_XOR_MULT_DOSStub_0ffa {
  strings:
    $key_0ffa = { 5b 92 [2] 2f 8a [2] 68 88 [2] 2f 99 [2] 61 95 [2] 6d 9f [2] 7a 94 [2] 61 da [2] 5c }

  condition:
    any of them
}