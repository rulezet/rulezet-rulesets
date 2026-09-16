rule TTP_XOR_MULT_DOSStub_4fb8 {
  strings:
    $key_4fb8 = { 1b d0 [2] 6f c8 [2] 28 ca [2] 6f db [2] 21 d7 [2] 2d dd [2] 3a d6 [2] 21 98 [2] 1c }

  condition:
    any of them
}