rule TTP_XOR_MULT_DOSStub_6fb8 {
  strings:
    $key_6fb8 = { 3b d0 [2] 4f c8 [2] 08 ca [2] 4f db [2] 01 d7 [2] 0d dd [2] 1a d6 [2] 01 98 [2] 3c }

  condition:
    any of them
}