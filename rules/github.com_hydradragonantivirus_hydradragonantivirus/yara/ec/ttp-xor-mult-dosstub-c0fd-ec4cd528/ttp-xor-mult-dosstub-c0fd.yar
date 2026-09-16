rule TTP_XOR_MULT_DOSStub_c0fd {
  strings:
    $key_c0fd = { 94 95 [2] e0 8d [2] a7 8f [2] e0 9e [2] ae 92 [2] a2 98 [2] b5 93 [2] ae dd [2] 93 }

  condition:
    any of them
}