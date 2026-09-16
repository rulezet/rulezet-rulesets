rule TTP_XOR_MULT_DOSStub_1fb8 {
  strings:
    $key_1fb8 = { 4b d0 [2] 3f c8 [2] 78 ca [2] 3f db [2] 71 d7 [2] 7d dd [2] 6a d6 [2] 71 98 [2] 4c }

  condition:
    any of them
}