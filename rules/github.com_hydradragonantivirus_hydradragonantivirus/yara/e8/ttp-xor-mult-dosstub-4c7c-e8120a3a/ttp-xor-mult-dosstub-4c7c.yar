rule TTP_XOR_MULT_DOSStub_4c7c {
  strings:
    $key_4c7c = { 18 14 [2] 6c 0c [2] 2b 0e [2] 6c 1f [2] 22 13 [2] 2e 19 [2] 39 12 [2] 22 5c [2] 1f }

  condition:
    any of them
}