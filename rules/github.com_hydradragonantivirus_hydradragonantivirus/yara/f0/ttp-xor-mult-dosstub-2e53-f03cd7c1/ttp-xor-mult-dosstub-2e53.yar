rule TTP_XOR_MULT_DOSStub_2e53 {
  strings:
    $key_2e53 = { 7a 3b [2] 0e 23 [2] 49 21 [2] 0e 30 [2] 40 3c [2] 4c 36 [2] 5b 3d [2] 40 73 [2] 7d }

  condition:
    any of them
}