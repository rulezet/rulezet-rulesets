rule TTP_XOR_MULT_DOSStub_4feb {
  strings:
    $key_4feb = { 1b 83 [2] 6f 9b [2] 28 99 [2] 6f 88 [2] 21 84 [2] 2d 8e [2] 3a 85 [2] 21 cb [2] 1c }

  condition:
    any of them
}