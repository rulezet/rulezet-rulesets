rule TTP_XOR_MULT_DOSStub_2fa5 {
  strings:
    $key_2fa5 = { 7b cd [2] 0f d5 [2] 48 d7 [2] 0f c6 [2] 41 ca [2] 4d c0 [2] 5a cb [2] 41 85 [2] 7c }

  condition:
    any of them
}