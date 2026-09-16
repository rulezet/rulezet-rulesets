rule TTP_XOR_MULT_DOSStub_e0fd {
  strings:
    $key_e0fd = { b4 95 [2] c0 8d [2] 87 8f [2] c0 9e [2] 8e 92 [2] 82 98 [2] 95 93 [2] 8e dd [2] b3 }

  condition:
    any of them
}