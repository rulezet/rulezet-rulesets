rule TTP_XOR_MULT_DOSStub_1e16 {
  strings:
    $key_1e16 = { 4a 7e [2] 3e 66 [2] 79 64 [2] 3e 75 [2] 70 79 [2] 7c 73 [2] 6b 78 [2] 70 36 [2] 4d }

  condition:
    any of them
}