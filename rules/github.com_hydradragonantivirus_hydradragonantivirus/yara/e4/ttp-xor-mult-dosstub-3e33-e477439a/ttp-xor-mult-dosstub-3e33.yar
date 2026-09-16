rule TTP_XOR_MULT_DOSStub_3e33 {
  strings:
    $key_3e33 = { 6a 5b [2] 1e 43 [2] 59 41 [2] 1e 50 [2] 50 5c [2] 5c 56 [2] 4b 5d [2] 50 13 [2] 6d }

  condition:
    any of them
}