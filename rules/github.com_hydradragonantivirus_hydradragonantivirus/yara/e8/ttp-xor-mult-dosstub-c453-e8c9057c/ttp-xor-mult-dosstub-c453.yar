rule TTP_XOR_MULT_DOSStub_c453 {
  strings:
    $key_c453 = { 90 3b [2] e4 23 [2] a3 21 [2] e4 30 [2] aa 3c [2] a6 36 [2] b1 3d [2] aa 73 [2] 97 }

  condition:
    any of them
}