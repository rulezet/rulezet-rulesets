rule TTP_XOR_MULT_DOSStub_7d4c {
  strings:
    $key_7d4c = { 29 24 [2] 5d 3c [2] 1a 3e [2] 5d 2f [2] 13 23 [2] 1f 29 [2] 08 22 [2] 13 6c [2] 2e }

  condition:
    any of them
}