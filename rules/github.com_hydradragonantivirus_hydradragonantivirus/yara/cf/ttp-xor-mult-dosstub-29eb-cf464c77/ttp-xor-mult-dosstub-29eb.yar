rule TTP_XOR_MULT_DOSStub_29eb {
  strings:
    $key_29eb = { 7d 83 [2] 09 9b [2] 4e 99 [2] 09 88 [2] 47 84 [2] 4b 8e [2] 5c 85 [2] 47 cb [2] 7a }

  condition:
    any of them
}