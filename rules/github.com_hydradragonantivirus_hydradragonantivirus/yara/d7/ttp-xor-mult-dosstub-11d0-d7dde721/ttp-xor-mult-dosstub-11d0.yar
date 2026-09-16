rule TTP_XOR_MULT_DOSStub_11d0 {
  strings:
    $key_11d0 = { 45 b8 [2] 31 a0 [2] 76 a2 [2] 31 b3 [2] 7f bf [2] 73 b5 [2] 64 be [2] 7f f0 [2] 42 }

  condition:
    any of them
}