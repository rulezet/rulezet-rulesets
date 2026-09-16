rule TTP_XOR_MULT_DOSStub_7bea {
  strings:
    $key_7bea = { 2f 82 [2] 5b 9a [2] 1c 98 [2] 5b 89 [2] 15 85 [2] 19 8f [2] 0e 84 [2] 15 ca [2] 28 }

  condition:
    any of them
}