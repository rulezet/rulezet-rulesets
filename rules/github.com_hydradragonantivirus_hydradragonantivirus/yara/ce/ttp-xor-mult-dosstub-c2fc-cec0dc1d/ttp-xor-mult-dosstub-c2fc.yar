rule TTP_XOR_MULT_DOSStub_c2fc {
  strings:
    $key_c2fc = { 96 94 [2] e2 8c [2] a5 8e [2] e2 9f [2] ac 93 [2] a0 99 [2] b7 92 [2] ac dc [2] 91 }

  condition:
    any of them
}