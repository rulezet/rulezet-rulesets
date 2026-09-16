rule TTP_XOR_MULT_DOSStub_d8ba {
  strings:
    $key_d8ba = { 8c d2 [2] f8 ca [2] bf c8 [2] f8 d9 [2] b6 d5 [2] ba df [2] ad d4 [2] b6 9a [2] 8b }

  condition:
    any of them
}