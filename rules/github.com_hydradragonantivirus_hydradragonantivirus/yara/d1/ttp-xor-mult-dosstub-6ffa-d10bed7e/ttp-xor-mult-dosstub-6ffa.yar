rule TTP_XOR_MULT_DOSStub_6ffa {
  strings:
    $key_6ffa = { 3b 92 [2] 4f 8a [2] 08 88 [2] 4f 99 [2] 01 95 [2] 0d 9f [2] 1a 94 [2] 01 da [2] 3c }

  condition:
    any of them
}