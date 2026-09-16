rule TTP_XOR_MULT_DOSStub_6dfd {
  strings:
    $key_6dfd = { 39 95 [2] 4d 8d [2] 0a 8f [2] 4d 9e [2] 03 92 [2] 0f 98 [2] 18 93 [2] 03 dd [2] 3e }

  condition:
    any of them
}