rule TTP_XOR_MULT_DOSStub_3beb {
  strings:
    $key_3beb = { 6f 83 [2] 1b 9b [2] 5c 99 [2] 1b 88 [2] 55 84 [2] 59 8e [2] 4e 85 [2] 55 cb [2] 68 }

  condition:
    any of them
}