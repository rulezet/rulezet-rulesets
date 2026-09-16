rule TTP_XOR_MULT_DOSStub_24b8 {
  strings:
    $key_24b8 = { 70 d0 [2] 04 c8 [2] 43 ca [2] 04 db [2] 4a d7 [2] 46 dd [2] 51 d6 [2] 4a 98 [2] 77 }

  condition:
    any of them
}