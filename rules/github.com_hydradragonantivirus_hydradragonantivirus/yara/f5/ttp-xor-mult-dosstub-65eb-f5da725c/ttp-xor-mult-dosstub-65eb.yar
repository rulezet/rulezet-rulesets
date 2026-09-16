rule TTP_XOR_MULT_DOSStub_65eb {
  strings:
    $key_65eb = { 31 83 [2] 45 9b [2] 02 99 [2] 45 88 [2] 0b 84 [2] 07 8e [2] 10 85 [2] 0b cb [2] 36 }

  condition:
    any of them
}