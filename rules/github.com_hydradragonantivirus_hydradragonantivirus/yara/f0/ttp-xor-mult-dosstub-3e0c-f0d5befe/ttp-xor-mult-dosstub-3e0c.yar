rule TTP_XOR_MULT_DOSStub_3e0c {
  strings:
    $key_3e0c = { 6a 64 [2] 1e 7c [2] 59 7e [2] 1e 6f [2] 50 63 [2] 5c 69 [2] 4b 62 [2] 50 2c [2] 6d }

  condition:
    any of them
}