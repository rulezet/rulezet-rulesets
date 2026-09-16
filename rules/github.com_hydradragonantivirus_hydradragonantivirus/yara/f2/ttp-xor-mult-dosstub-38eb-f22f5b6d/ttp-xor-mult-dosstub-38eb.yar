rule TTP_XOR_MULT_DOSStub_38eb {
  strings:
    $key_38eb = { 6c 83 [2] 18 9b [2] 5f 99 [2] 18 88 [2] 56 84 [2] 5a 8e [2] 4d 85 [2] 56 cb [2] 6b }

  condition:
    any of them
}