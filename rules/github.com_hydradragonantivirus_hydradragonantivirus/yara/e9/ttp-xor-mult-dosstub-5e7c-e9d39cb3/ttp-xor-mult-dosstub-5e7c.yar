rule TTP_XOR_MULT_DOSStub_5e7c {
  strings:
    $key_5e7c = { 0a 14 [2] 7e 0c [2] 39 0e [2] 7e 1f [2] 30 13 [2] 3c 19 [2] 2b 12 [2] 30 5c [2] 0d }

  condition:
    any of them
}