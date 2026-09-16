rule TTP_XOR_MULT_DOSStub_3e04 {
  strings:
    $key_3e04 = { 6a 6c [2] 1e 74 [2] 59 76 [2] 1e 67 [2] 50 6b [2] 5c 61 [2] 4b 6a [2] 50 24 [2] 6d }

  condition:
    any of them
}