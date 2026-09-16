rule TTP_XOR_MULT_DOSStub_6a2c {
  strings:
    $key_6a2c = { 3e 44 [2] 4a 5c [2] 0d 5e [2] 4a 4f [2] 04 43 [2] 08 49 [2] 1f 42 [2] 04 0c [2] 39 }

  condition:
    any of them
}