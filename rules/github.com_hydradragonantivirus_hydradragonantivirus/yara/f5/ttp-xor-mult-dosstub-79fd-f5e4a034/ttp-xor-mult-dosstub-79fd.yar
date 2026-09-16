rule TTP_XOR_MULT_DOSStub_79fd {
  strings:
    $key_79fd = { 2d 95 [2] 59 8d [2] 1e 8f [2] 59 9e [2] 17 92 [2] 1b 98 [2] 0c 93 [2] 17 dd [2] 2a }

  condition:
    any of them
}