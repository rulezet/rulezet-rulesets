rule TTP_XOR_MULT_DOSStub_0bfa {
  strings:
    $key_0bfa = { 5f 92 [2] 2b 8a [2] 6c 88 [2] 2b 99 [2] 65 95 [2] 69 9f [2] 7e 94 [2] 65 da [2] 58 }

  condition:
    any of them
}