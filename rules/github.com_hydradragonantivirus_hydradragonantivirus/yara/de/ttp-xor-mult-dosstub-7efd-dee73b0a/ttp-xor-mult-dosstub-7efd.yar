rule TTP_XOR_MULT_DOSStub_7efd {
  strings:
    $key_7efd = { 2a 95 [2] 5e 8d [2] 19 8f [2] 5e 9e [2] 10 92 [2] 1c 98 [2] 0b 93 [2] 10 dd [2] 2d }

  condition:
    any of them
}