rule TTP_XOR_MULT_DOSStub_fca2 {
  strings:
    $key_fca2 = { a8 ca [2] dc d2 [2] 9b d0 [2] dc c1 [2] 92 cd [2] 9e c7 [2] 89 cc [2] 92 82 [2] af }

  condition:
    any of them
}