rule TTP_XOR_MULT_DOSStub_4a43 {
  strings:
    $key_4a43 = { 1e 2b [2] 6a 33 [2] 2d 31 [2] 6a 20 [2] 24 2c [2] 28 26 [2] 3f 2d [2] 24 63 [2] 19 }

  condition:
    any of them
}