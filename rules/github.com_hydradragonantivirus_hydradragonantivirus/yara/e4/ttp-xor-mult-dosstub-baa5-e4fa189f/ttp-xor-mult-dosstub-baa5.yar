rule TTP_XOR_MULT_DOSStub_baa5 {
  strings:
    $key_baa5 = { ee cd [2] 9a d5 [2] dd d7 [2] 9a c6 [2] d4 ca [2] d8 c0 [2] cf cb [2] d4 85 [2] e9 }

  condition:
    any of them
}