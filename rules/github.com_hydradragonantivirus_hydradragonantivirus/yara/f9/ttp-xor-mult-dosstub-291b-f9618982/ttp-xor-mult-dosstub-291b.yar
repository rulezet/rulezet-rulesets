rule TTP_XOR_MULT_DOSStub_291b {
  strings:
    $key_291b = { 7d 73 [2] 09 6b [2] 4e 69 [2] 09 78 [2] 47 74 [2] 4b 7e [2] 5c 75 [2] 47 3b [2] 7a }

  condition:
    any of them
}