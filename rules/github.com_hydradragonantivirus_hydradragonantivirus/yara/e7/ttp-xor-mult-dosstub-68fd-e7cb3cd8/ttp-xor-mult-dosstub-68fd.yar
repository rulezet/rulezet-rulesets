rule TTP_XOR_MULT_DOSStub_68fd {
  strings:
    $key_68fd = { 3c 95 [2] 48 8d [2] 0f 8f [2] 48 9e [2] 06 92 [2] 0a 98 [2] 1d 93 [2] 06 dd [2] 3b }

  condition:
    any of them
}