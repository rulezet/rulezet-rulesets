rule TTP_XOR_MULT_DOSStub_5b2c {
  strings:
    $key_5b2c = { 0f 44 [2] 7b 5c [2] 3c 5e [2] 7b 4f [2] 35 43 [2] 39 49 [2] 2e 42 [2] 35 0c [2] 08 }

  condition:
    any of them
}