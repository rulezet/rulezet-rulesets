rule TTP_XOR_MULT_DOSStub_25ab {
  strings:
    $key_25ab = { 71 c3 [2] 05 db [2] 42 d9 [2] 05 c8 [2] 4b c4 [2] 47 ce [2] 50 c5 [2] 4b 8b [2] 76 }

  condition:
    any of them
}