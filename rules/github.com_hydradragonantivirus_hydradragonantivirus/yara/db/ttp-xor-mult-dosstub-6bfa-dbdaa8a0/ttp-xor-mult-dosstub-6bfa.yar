rule TTP_XOR_MULT_DOSStub_6bfa {
  strings:
    $key_6bfa = { 3f 92 [2] 4b 8a [2] 0c 88 [2] 4b 99 [2] 05 95 [2] 09 9f [2] 1e 94 [2] 05 da [2] 38 }

  condition:
    any of them
}