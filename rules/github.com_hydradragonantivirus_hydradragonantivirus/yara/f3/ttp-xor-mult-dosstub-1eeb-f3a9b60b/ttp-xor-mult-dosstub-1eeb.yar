rule TTP_XOR_MULT_DOSStub_1eeb {
  strings:
    $key_1eeb = { 4a 83 [2] 3e 9b [2] 79 99 [2] 3e 88 [2] 70 84 [2] 7c 8e [2] 6b 85 [2] 70 cb [2] 4d }

  condition:
    any of them
}