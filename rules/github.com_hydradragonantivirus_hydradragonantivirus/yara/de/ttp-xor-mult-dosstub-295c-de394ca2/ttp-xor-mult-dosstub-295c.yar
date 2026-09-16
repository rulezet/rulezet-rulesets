rule TTP_XOR_MULT_DOSStub_295c {
  strings:
    $key_295c = { 7d 34 [2] 09 2c [2] 4e 2e [2] 09 3f [2] 47 33 [2] 4b 39 [2] 5c 32 [2] 47 7c [2] 7a }

  condition:
    any of them
}