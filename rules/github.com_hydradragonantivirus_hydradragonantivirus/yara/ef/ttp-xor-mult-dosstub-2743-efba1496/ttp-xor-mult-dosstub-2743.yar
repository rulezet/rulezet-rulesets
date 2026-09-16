rule TTP_XOR_MULT_DOSStub_2743 {
  strings:
    $key_2743 = { 73 2b [2] 07 33 [2] 40 31 [2] 07 20 [2] 49 2c [2] 45 26 [2] 52 2d [2] 49 63 [2] 74 }

  condition:
    any of them
}