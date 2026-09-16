rule TTP_XOR_MULT_DOSStub_e443 {
  strings:
    $key_e443 = { b0 2b [2] c4 33 [2] 83 31 [2] c4 20 [2] 8a 2c [2] 86 26 [2] 91 2d [2] 8a 63 [2] b7 }

  condition:
    any of them
}