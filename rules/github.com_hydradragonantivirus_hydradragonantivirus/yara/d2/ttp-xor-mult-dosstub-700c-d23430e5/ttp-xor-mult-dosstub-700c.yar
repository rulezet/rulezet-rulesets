rule TTP_XOR_MULT_DOSStub_700c {
  strings:
    $key_700c = { 24 64 [2] 50 7c [2] 17 7e [2] 50 6f [2] 1e 63 [2] 12 69 [2] 05 62 [2] 1e 2c [2] 23 }

  condition:
    any of them
}