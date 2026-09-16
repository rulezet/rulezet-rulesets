rule TTP_XOR_MULT_DOSStub_7a43 {
  strings:
    $key_7a43 = { 2e 2b [2] 5a 33 [2] 1d 31 [2] 5a 20 [2] 14 2c [2] 18 26 [2] 0f 2d [2] 14 63 [2] 29 }

  condition:
    any of them
}