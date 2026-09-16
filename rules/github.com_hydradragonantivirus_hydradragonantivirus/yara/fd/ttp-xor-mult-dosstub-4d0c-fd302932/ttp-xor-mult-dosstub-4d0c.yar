rule TTP_XOR_MULT_DOSStub_4d0c {
  strings:
    $key_4d0c = { 19 64 [2] 6d 7c [2] 2a 7e [2] 6d 6f [2] 23 63 [2] 2f 69 [2] 38 62 [2] 23 2c [2] 1e }

  condition:
    any of them
}