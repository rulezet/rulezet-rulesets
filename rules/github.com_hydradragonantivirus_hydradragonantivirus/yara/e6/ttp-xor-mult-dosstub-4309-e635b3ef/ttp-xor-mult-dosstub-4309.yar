rule TTP_XOR_MULT_DOSStub_4309 {
  strings:
    $key_4309 = { 17 61 [2] 63 79 [2] 24 7b [2] 63 6a [2] 2d 66 [2] 21 6c [2] 36 67 [2] 2d 29 [2] 10 }

  condition:
    any of them
}