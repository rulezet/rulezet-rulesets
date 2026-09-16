rule TTP_XOR_MULT_DOSStub_fcfd {
  strings:
    $key_fcfd = { a8 95 [2] dc 8d [2] 9b 8f [2] dc 9e [2] 92 92 [2] 9e 98 [2] 89 93 [2] 92 dd [2] af }

  condition:
    any of them
}