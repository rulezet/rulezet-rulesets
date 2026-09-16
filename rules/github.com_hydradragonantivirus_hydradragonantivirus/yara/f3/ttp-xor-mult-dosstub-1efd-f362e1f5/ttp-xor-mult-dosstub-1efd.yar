rule TTP_XOR_MULT_DOSStub_1efd {
  strings:
    $key_1efd = { 4a 95 [2] 3e 8d [2] 79 8f [2] 3e 9e [2] 70 92 [2] 7c 98 [2] 6b 93 [2] 70 dd [2] 4d }

  condition:
    any of them
}