rule TTP_XOR_MULT_DOSStub_6efd {
  strings:
    $key_6efd = { 3a 95 [2] 4e 8d [2] 09 8f [2] 4e 9e [2] 00 92 [2] 0c 98 [2] 1b 93 [2] 00 dd [2] 3d }

  condition:
    any of them
}