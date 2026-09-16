rule TTP_XOR_MULT_DOSStub_09eb {
  strings:
    $key_09eb = { 5d 83 [2] 29 9b [2] 6e 99 [2] 29 88 [2] 67 84 [2] 6b 8e [2] 7c 85 [2] 67 cb [2] 5a }

  condition:
    any of them
}