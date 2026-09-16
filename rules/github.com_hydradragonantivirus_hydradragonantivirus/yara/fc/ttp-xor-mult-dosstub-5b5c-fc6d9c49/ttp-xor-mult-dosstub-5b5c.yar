rule TTP_XOR_MULT_DOSStub_5b5c {
  strings:
    $key_5b5c = { 0f 34 [2] 7b 2c [2] 3c 2e [2] 7b 3f [2] 35 33 [2] 39 39 [2] 2e 32 [2] 35 7c [2] 08 }

  condition:
    any of them
}