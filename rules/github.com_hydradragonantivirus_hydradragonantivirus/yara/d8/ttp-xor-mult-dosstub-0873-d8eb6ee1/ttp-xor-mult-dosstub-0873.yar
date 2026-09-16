rule TTP_XOR_MULT_DOSStub_0873 {
  strings:
    $key_0873 = { 5c 1b [2] 28 03 [2] 6f 01 [2] 28 10 [2] 66 1c [2] 6a 16 [2] 7d 1d [2] 66 53 [2] 5b }

  condition:
    any of them
}