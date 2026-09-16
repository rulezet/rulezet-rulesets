rule TTP_XOR_MULT_DOSStub_e473 {
  strings:
    $key_e473 = { b0 1b [2] c4 03 [2] 83 01 [2] c4 10 [2] 8a 1c [2] 86 16 [2] 91 1d [2] 8a 53 [2] b7 }

  condition:
    any of them
}