rule TTP_XOR_MULT_DOSStub_0e0c {
  strings:
    $key_0e0c = { 5a 64 [2] 2e 7c [2] 69 7e [2] 2e 6f [2] 60 63 [2] 6c 69 [2] 7b 62 [2] 60 2c [2] 5d }

  condition:
    any of them
}