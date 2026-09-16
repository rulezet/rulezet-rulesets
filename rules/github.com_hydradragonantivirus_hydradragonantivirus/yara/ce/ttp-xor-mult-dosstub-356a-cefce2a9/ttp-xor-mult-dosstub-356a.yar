rule TTP_XOR_MULT_DOSStub_356a {
  strings:
    $key_356a = { 61 02 [2] 15 1a [2] 52 18 [2] 15 09 [2] 5b 05 [2] 57 0f [2] 40 04 [2] 5b 4a [2] 66 }

  condition:
    any of them
}