rule TTP_XOR_MULT_DOSStub_6e5c {
  strings:
    $key_6e5c = { 3a 34 [2] 4e 2c [2] 09 2e [2] 4e 3f [2] 00 33 [2] 0c 39 [2] 1b 32 [2] 00 7c [2] 3d }

  condition:
    any of them
}