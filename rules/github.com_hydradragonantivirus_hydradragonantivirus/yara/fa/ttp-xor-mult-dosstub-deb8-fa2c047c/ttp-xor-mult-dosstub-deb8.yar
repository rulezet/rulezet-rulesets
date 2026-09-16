rule TTP_XOR_MULT_DOSStub_deb8 {
  strings:
    $key_deb8 = { 8a d0 [2] fe c8 [2] b9 ca [2] fe db [2] b0 d7 [2] bc dd [2] ab d6 [2] b0 98 [2] 8d }

  condition:
    any of them
}