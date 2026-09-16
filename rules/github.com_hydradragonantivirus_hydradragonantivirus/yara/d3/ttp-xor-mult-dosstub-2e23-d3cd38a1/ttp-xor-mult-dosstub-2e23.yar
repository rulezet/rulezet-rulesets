rule TTP_XOR_MULT_DOSStub_2e23 {
  strings:
    $key_2e23 = { 7a 4b [2] 0e 53 [2] 49 51 [2] 0e 40 [2] 40 4c [2] 4c 46 [2] 5b 4d [2] 40 03 [2] 7d }

  condition:
    any of them
}