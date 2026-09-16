rule TTP_XOR_MULT_DOSStub_0df0 {
  strings:
    $key_0df0 = { 59 98 [2] 2d 80 [2] 6a 82 [2] 2d 93 [2] 63 9f [2] 6f 95 [2] 78 9e [2] 63 d0 [2] 5e }

  condition:
    any of them
}