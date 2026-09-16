rule TTP_XOR_MULT_DOSStub_3e26 {
  strings:
    $key_3e26 = { 6a 4e [2] 1e 56 [2] 59 54 [2] 1e 45 [2] 50 49 [2] 5c 43 [2] 4b 48 [2] 50 06 [2] 6d }

  condition:
    any of them
}