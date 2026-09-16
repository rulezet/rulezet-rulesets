rule TTP_XOR_MULT_DOSStub_5e31 {
  strings:
    $key_5e31 = { 0a 59 [2] 7e 41 [2] 39 43 [2] 7e 52 [2] 30 5e [2] 3c 54 [2] 2b 5f [2] 30 11 [2] 0d }

  condition:
    any of them
}