rule TTP_XOR_MULT_DOSStub_283c {
  strings:
    $key_283c = { 7c 54 [2] 08 4c [2] 4f 4e [2] 08 5f [2] 46 53 [2] 4a 59 [2] 5d 52 [2] 46 1c [2] 7b }

  condition:
    any of them
}