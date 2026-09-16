rule TTP_XOR_MULT_DOSStub_2e71 {
  strings:
    $key_2e71 = { 7a 19 [2] 0e 01 [2] 49 03 [2] 0e 12 [2] 40 1e [2] 4c 14 [2] 5b 1f [2] 40 51 [2] 7d }

  condition:
    any of them
}