rule TTP_XOR_MULT_DOSStub_08b8 {
  strings:
    $key_08b8 = { 5c d0 [2] 28 c8 [2] 6f ca [2] 28 db [2] 66 d7 [2] 6a dd [2] 7d d6 [2] 66 98 [2] 5b }

  condition:
    any of them
}