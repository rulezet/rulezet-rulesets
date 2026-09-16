rule TTP_XOR_MULT_DOSStub_c9a5 {
  strings:
    $key_c9a5 = { 9d cd [2] e9 d5 [2] ae d7 [2] e9 c6 [2] a7 ca [2] ab c0 [2] bc cb [2] a7 85 [2] 9a }

  condition:
    any of them
}