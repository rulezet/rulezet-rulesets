rule TTP_XOR_MULT_DOSStub_1ceb {
  strings:
    $key_1ceb = { 48 83 [2] 3c 9b [2] 7b 99 [2] 3c 88 [2] 72 84 [2] 7e 8e [2] 69 85 [2] 72 cb [2] 4f }

  condition:
    any of them
}