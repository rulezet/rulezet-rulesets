rule TTP_XOR_MULT_DOSStub_5e29 {
  strings:
    $key_5e29 = { 0a 41 [2] 7e 59 [2] 39 5b [2] 7e 4a [2] 30 46 [2] 3c 4c [2] 2b 47 [2] 30 09 [2] 0d }

  condition:
    any of them
}