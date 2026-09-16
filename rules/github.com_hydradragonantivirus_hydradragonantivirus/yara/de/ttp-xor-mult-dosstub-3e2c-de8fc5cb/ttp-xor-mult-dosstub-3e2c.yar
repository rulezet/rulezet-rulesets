rule TTP_XOR_MULT_DOSStub_3e2c {
  strings:
    $key_3e2c = { 6a 44 [2] 1e 5c [2] 59 5e [2] 1e 4f [2] 50 43 [2] 5c 49 [2] 4b 42 [2] 50 0c [2] 6d }

  condition:
    any of them
}