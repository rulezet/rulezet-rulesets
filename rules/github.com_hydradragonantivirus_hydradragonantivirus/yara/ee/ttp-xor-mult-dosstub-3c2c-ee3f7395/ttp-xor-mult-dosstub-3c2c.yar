rule TTP_XOR_MULT_DOSStub_3c2c {
  strings:
    $key_3c2c = { 68 44 [2] 1c 5c [2] 5b 5e [2] 1c 4f [2] 52 43 [2] 5e 49 [2] 49 42 [2] 52 0c [2] 6f }

  condition:
    any of them
}