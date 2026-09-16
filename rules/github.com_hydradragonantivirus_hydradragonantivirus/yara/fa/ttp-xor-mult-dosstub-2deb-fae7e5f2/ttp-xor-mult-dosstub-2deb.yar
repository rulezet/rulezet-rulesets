rule TTP_XOR_MULT_DOSStub_2deb {
  strings:
    $key_2deb = { 79 83 [2] 0d 9b [2] 4a 99 [2] 0d 88 [2] 43 84 [2] 4f 8e [2] 58 85 [2] 43 cb [2] 7e }

  condition:
    any of them
}