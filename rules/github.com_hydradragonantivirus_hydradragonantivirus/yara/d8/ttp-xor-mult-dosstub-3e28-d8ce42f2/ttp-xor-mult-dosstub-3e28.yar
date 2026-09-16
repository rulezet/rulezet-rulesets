rule TTP_XOR_MULT_DOSStub_3e28 {
  strings:
    $key_3e28 = { 6a 40 [2] 1e 58 [2] 59 5a [2] 1e 4b [2] 50 47 [2] 5c 4d [2] 4b 46 [2] 50 08 [2] 6d }

  condition:
    any of them
}