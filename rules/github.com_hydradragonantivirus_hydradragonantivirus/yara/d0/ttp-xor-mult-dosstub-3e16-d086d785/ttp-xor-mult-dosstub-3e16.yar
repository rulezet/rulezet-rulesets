rule TTP_XOR_MULT_DOSStub_3e16 {
  strings:
    $key_3e16 = { 6a 7e [2] 1e 66 [2] 59 64 [2] 1e 75 [2] 50 79 [2] 5c 73 [2] 4b 78 [2] 50 36 [2] 6d }

  condition:
    any of them
}