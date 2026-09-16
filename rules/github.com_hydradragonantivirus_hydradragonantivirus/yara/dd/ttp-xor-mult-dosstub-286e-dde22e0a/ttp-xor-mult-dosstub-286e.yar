rule TTP_XOR_MULT_DOSStub_286e {
  strings:
    $key_286e = { 7c 06 [2] 08 1e [2] 4f 1c [2] 08 0d [2] 46 01 [2] 4a 0b [2] 5d 00 [2] 46 4e [2] 7b }

  condition:
    any of them
}