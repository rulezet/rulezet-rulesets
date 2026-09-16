rule TTP_XOR_MULT_DOSStub_6876 {
  strings:
    $key_6876 = { 3c 1e [2] 48 06 [2] 0f 04 [2] 48 15 [2] 06 19 [2] 0a 13 [2] 1d 18 [2] 06 56 [2] 3b }

  condition:
    any of them
}