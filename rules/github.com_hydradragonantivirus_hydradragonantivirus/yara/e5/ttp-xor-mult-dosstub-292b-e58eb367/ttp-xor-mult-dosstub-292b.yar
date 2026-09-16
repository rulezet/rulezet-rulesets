rule TTP_XOR_MULT_DOSStub_292b {
  strings:
    $key_292b = { 7d 43 [2] 09 5b [2] 4e 59 [2] 09 48 [2] 47 44 [2] 4b 4e [2] 5c 45 [2] 47 0b [2] 7a }

  condition:
    any of them
}