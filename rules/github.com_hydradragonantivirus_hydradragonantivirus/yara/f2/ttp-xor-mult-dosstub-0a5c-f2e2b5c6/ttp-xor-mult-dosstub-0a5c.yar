rule TTP_XOR_MULT_DOSStub_0a5c {
  strings:
    $key_0a5c = { 5e 34 [2] 2a 2c [2] 6d 2e [2] 2a 3f [2] 64 33 [2] 68 39 [2] 7f 32 [2] 64 7c [2] 59 }

  condition:
    any of them
}