rule TTP_XOR_MULT_DOSStub_7e26 {
  strings:
    $key_7e26 = { 2a 4e [2] 5e 56 [2] 19 54 [2] 5e 45 [2] 10 49 [2] 1c 43 [2] 0b 48 [2] 10 06 [2] 2d }

  condition:
    any of them
}