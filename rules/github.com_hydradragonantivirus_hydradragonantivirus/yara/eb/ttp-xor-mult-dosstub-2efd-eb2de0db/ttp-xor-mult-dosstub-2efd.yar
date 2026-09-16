rule TTP_XOR_MULT_DOSStub_2efd {
  strings:
    $key_2efd = { 7a 95 [2] 0e 8d [2] 49 8f [2] 0e 9e [2] 40 92 [2] 4c 98 [2] 5b 93 [2] 40 dd [2] 7d }

  condition:
    any of them
}