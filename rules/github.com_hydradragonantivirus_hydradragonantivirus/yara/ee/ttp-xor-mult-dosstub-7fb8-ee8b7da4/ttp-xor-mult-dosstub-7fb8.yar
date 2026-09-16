rule TTP_XOR_MULT_DOSStub_7fb8 {
  strings:
    $key_7fb8 = { 2b d0 [2] 5f c8 [2] 18 ca [2] 5f db [2] 11 d7 [2] 1d dd [2] 0a d6 [2] 11 98 [2] 2c }

  condition:
    any of them
}