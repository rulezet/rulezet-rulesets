rule TTP_XOR_MULT_DOSStub_297b {
  strings:
    $key_297b = { 7d 13 [2] 09 0b [2] 4e 09 [2] 09 18 [2] 47 14 [2] 4b 1e [2] 5c 15 [2] 47 5b [2] 7a }

  condition:
    any of them
}