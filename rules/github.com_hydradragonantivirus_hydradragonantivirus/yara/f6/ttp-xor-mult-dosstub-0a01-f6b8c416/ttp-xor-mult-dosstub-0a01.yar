rule TTP_XOR_MULT_DOSStub_0a01 {
  strings:
    $key_0a01 = { 5e 69 [2] 2a 71 [2] 6d 73 [2] 2a 62 [2] 64 6e [2] 68 64 [2] 7f 6f [2] 64 21 [2] 59 }

  condition:
    any of them
}