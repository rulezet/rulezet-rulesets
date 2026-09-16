rule TTP_XOR_MULT_DOSStub_5e51 {
  strings:
    $key_5e51 = { 0a 39 [2] 7e 21 [2] 39 23 [2] 7e 32 [2] 30 3e [2] 3c 34 [2] 2b 3f [2] 30 71 [2] 0d }

  condition:
    any of them
}