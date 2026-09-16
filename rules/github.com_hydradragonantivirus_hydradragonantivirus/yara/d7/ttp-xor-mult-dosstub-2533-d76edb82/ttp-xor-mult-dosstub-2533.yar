rule TTP_XOR_MULT_DOSStub_2533 {
  strings:
    $key_2533 = { 71 5b [2] 05 43 [2] 42 41 [2] 05 50 [2] 4b 5c [2] 47 56 [2] 50 5d [2] 4b 13 [2] 76 }

  condition:
    any of them
}