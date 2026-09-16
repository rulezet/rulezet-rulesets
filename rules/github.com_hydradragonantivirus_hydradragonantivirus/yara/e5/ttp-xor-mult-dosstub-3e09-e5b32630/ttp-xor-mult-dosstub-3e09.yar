rule TTP_XOR_MULT_DOSStub_3e09 {
  strings:
    $key_3e09 = { 6a 61 [2] 1e 79 [2] 59 7b [2] 1e 6a [2] 50 66 [2] 5c 6c [2] 4b 67 [2] 50 29 [2] 6d }

  condition:
    any of them
}