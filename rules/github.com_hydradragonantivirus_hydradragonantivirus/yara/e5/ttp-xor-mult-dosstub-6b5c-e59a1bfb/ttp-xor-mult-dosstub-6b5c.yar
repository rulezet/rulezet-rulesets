rule TTP_XOR_MULT_DOSStub_6b5c {
  strings:
    $key_6b5c = { 3f 34 [2] 4b 2c [2] 0c 2e [2] 4b 3f [2] 05 33 [2] 09 39 [2] 1e 32 [2] 05 7c [2] 38 }

  condition:
    any of them
}