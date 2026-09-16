rule TTP_XOR_MULT_DOSStub_2eeb {
  strings:
    $key_2eeb = { 7a 83 [2] 0e 9b [2] 49 99 [2] 0e 88 [2] 40 84 [2] 4c 8e [2] 5b 85 [2] 40 cb [2] 7d }

  condition:
    any of them
}