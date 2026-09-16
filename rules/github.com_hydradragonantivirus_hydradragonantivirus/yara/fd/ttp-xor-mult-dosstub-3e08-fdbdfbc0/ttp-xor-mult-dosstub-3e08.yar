rule TTP_XOR_MULT_DOSStub_3e08 {
  strings:
    $key_3e08 = { 6a 60 [2] 1e 78 [2] 59 7a [2] 1e 6b [2] 50 67 [2] 5c 6d [2] 4b 66 [2] 50 28 [2] 6d }

  condition:
    any of them
}