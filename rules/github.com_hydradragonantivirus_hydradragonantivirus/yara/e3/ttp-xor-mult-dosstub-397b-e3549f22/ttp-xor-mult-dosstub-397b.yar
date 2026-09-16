rule TTP_XOR_MULT_DOSStub_397b {
  strings:
    $key_397b = { 6d 13 [2] 19 0b [2] 5e 09 [2] 19 18 [2] 57 14 [2] 5b 1e [2] 4c 15 [2] 57 5b [2] 6a }

  condition:
    any of them
}