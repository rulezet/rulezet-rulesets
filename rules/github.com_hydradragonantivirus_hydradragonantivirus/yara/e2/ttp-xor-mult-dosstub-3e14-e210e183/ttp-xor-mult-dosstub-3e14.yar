rule TTP_XOR_MULT_DOSStub_3e14 {
  strings:
    $key_3e14 = { 6a 7c [2] 1e 64 [2] 59 66 [2] 1e 77 [2] 50 7b [2] 5c 71 [2] 4b 7a [2] 50 34 [2] 6d }

  condition:
    any of them
}