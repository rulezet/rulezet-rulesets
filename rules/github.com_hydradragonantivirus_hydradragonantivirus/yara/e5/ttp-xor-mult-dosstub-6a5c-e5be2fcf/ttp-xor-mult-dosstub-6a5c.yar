rule TTP_XOR_MULT_DOSStub_6a5c {
  strings:
    $key_6a5c = { 3e 34 [2] 4a 2c [2] 0d 2e [2] 4a 3f [2] 04 33 [2] 08 39 [2] 1f 32 [2] 04 7c [2] 39 }

  condition:
    any of them
}