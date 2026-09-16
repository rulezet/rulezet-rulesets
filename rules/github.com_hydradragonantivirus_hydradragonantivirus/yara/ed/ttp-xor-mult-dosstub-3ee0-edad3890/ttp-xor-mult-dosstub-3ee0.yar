rule TTP_XOR_MULT_DOSStub_3ee0 {
  strings:
    $key_3ee0 = { 6a 88 [2] 1e 90 [2] 59 92 [2] 1e 83 [2] 50 8f [2] 5c 85 [2] 4b 8e [2] 50 c0 [2] 6d }

  condition:
    any of them
}