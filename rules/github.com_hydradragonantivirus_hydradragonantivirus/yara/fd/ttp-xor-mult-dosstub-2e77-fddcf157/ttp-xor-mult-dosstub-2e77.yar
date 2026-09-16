rule TTP_XOR_MULT_DOSStub_2e77 {
  strings:
    $key_2e77 = { 7a 1f [2] 0e 07 [2] 49 05 [2] 0e 14 [2] 40 18 [2] 4c 12 [2] 5b 19 [2] 40 57 [2] 7d }

  condition:
    any of them
}