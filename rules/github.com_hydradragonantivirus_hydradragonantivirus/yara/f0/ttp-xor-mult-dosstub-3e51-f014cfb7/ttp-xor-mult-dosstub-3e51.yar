rule TTP_XOR_MULT_DOSStub_3e51 {
  strings:
    $key_3e51 = { 6a 39 [2] 1e 21 [2] 59 23 [2] 1e 32 [2] 50 3e [2] 5c 34 [2] 4b 3f [2] 50 71 [2] 6d }

  condition:
    any of them
}