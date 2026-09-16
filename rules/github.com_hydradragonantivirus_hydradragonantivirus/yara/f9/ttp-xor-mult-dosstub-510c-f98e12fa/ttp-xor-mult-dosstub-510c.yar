rule TTP_XOR_MULT_DOSStub_510c {
  strings:
    $key_510c = { 05 64 [2] 71 7c [2] 36 7e [2] 71 6f [2] 3f 63 [2] 33 69 [2] 24 62 [2] 3f 2c [2] 02 }

  condition:
    any of them
}