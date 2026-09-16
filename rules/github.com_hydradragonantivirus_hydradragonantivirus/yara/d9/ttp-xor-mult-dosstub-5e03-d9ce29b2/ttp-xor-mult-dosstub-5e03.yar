rule TTP_XOR_MULT_DOSStub_5e03 {
  strings:
    $key_5e03 = { 0a 6b [2] 7e 73 [2] 39 71 [2] 7e 60 [2] 30 6c [2] 3c 66 [2] 2b 6d [2] 30 23 [2] 0d }

  condition:
    any of them
}