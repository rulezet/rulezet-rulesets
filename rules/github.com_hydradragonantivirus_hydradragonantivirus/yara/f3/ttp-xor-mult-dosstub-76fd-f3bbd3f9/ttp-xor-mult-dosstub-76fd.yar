rule TTP_XOR_MULT_DOSStub_76fd {
  strings:
    $key_76fd = { 22 95 [2] 56 8d [2] 11 8f [2] 56 9e [2] 18 92 [2] 14 98 [2] 03 93 [2] 18 dd [2] 25 }

  condition:
    any of them
}