rule TTP_XOR_MULT_DOSStub_045c {
  strings:
    $key_045c = { 50 34 [2] 24 2c [2] 63 2e [2] 24 3f [2] 6a 33 [2] 66 39 [2] 71 32 [2] 6a 7c [2] 57 }

  condition:
    any of them
}