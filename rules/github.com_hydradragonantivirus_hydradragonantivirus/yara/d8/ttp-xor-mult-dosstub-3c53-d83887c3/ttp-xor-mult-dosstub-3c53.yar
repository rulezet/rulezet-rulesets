rule TTP_XOR_MULT_DOSStub_3c53 {
  strings:
    $key_3c53 = { 68 3b [2] 1c 23 [2] 5b 21 [2] 1c 30 [2] 52 3c [2] 5e 36 [2] 49 3d [2] 52 73 [2] 6f }

  condition:
    any of them
}