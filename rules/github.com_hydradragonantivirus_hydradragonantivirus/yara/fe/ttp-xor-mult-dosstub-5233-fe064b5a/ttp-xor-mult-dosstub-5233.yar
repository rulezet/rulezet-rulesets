rule TTP_XOR_MULT_DOSStub_5233 {
  strings:
    $key_5233 = { 06 5b [2] 72 43 [2] 35 41 [2] 72 50 [2] 3c 5c [2] 30 56 [2] 27 5d [2] 3c 13 [2] 01 }

  condition:
    any of them
}