rule TTP_XOR_MULT_DOSStub_71fd {
  strings:
    $key_71fd = { 25 95 [2] 51 8d [2] 16 8f [2] 51 9e [2] 1f 92 [2] 13 98 [2] 04 93 [2] 1f dd [2] 22 }

  condition:
    any of them
}