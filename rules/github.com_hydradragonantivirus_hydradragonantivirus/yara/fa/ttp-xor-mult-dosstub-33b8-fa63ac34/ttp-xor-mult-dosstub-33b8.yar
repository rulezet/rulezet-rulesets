rule TTP_XOR_MULT_DOSStub_33b8 {
  strings:
    $key_33b8 = { 67 d0 [2] 13 c8 [2] 54 ca [2] 13 db [2] 5d d7 [2] 51 dd [2] 46 d6 [2] 5d 98 [2] 60 }

  condition:
    any of them
}