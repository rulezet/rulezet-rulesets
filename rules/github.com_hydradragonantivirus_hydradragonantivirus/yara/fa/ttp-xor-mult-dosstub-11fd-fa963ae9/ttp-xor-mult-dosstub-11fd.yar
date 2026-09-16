rule TTP_XOR_MULT_DOSStub_11fd {
  strings:
    $key_11fd = { 45 95 [2] 31 8d [2] 76 8f [2] 31 9e [2] 7f 92 [2] 73 98 [2] 64 93 [2] 7f dd [2] 42 }

  condition:
    any of them
}