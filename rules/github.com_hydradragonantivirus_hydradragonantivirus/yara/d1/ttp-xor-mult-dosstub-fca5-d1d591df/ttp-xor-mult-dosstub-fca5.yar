rule TTP_XOR_MULT_DOSStub_fca5 {
  strings:
    $key_fca5 = { a8 cd [2] dc d5 [2] 9b d7 [2] dc c6 [2] 92 ca [2] 9e c0 [2] 89 cb [2] 92 85 [2] af }

  condition:
    any of them
}