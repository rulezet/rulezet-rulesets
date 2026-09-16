rule TTP_XOR_MULT_DOSStub_2e5c {
  strings:
    $key_2e5c = { 7a 34 [2] 0e 2c [2] 49 2e [2] 0e 3f [2] 40 33 [2] 4c 39 [2] 5b 32 [2] 40 7c [2] 7d }

  condition:
    any of them
}