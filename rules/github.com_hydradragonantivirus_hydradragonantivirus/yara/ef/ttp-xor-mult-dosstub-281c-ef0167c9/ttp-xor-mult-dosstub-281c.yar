rule TTP_XOR_MULT_DOSStub_281c {
  strings:
    $key_281c = { 7c 74 [2] 08 6c [2] 4f 6e [2] 08 7f [2] 46 73 [2] 4a 79 [2] 5d 72 [2] 46 3c [2] 7b }

  condition:
    any of them
}