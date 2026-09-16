rule TTP_XOR_MULT_DOSStub_28fd {
  strings:
    $key_28fd = { 7c 95 [2] 08 8d [2] 4f 8f [2] 08 9e [2] 46 92 [2] 4a 98 [2] 5d 93 [2] 46 dd [2] 7b }

  condition:
    any of them
}