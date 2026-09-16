rule TTP_XOR_MULT_DOSStub_0beb {
  strings:
    $key_0beb = { 5f 83 [2] 2b 9b [2] 6c 99 [2] 2b 88 [2] 65 84 [2] 69 8e [2] 7e 85 [2] 65 cb [2] 58 }

  condition:
    any of them
}