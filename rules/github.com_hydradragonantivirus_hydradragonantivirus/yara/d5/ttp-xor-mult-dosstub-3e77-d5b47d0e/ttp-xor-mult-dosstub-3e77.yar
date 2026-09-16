rule TTP_XOR_MULT_DOSStub_3e77 {
  strings:
    $key_3e77 = { 6a 1f [2] 1e 07 [2] 59 05 [2] 1e 14 [2] 50 18 [2] 5c 12 [2] 4b 19 [2] 50 57 [2] 6d }

  condition:
    any of them
}