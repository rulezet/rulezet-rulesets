rule TTP_XOR_MULT_DOSStub_3ffd {
  strings:
    $key_3ffd = { 6b 95 [2] 1f 8d [2] 58 8f [2] 1f 9e [2] 51 92 [2] 5d 98 [2] 4a 93 [2] 51 dd [2] 6c }

  condition:
    any of them
}