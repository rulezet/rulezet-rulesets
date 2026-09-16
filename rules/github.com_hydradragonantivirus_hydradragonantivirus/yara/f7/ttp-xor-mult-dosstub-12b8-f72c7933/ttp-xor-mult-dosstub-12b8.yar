rule TTP_XOR_MULT_DOSStub_12b8 {
  strings:
    $key_12b8 = { 46 d0 [2] 32 c8 [2] 75 ca [2] 32 db [2] 7c d7 [2] 70 dd [2] 67 d6 [2] 7c 98 [2] 41 }

  condition:
    any of them
}