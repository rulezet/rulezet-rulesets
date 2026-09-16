rule TTP_XOR_MULT_DOSStub_c2ad {
  strings:
    $key_c2ad = { 96 c5 [2] e2 dd [2] a5 df [2] e2 ce [2] ac c2 [2] a0 c8 [2] b7 c3 [2] ac 8d [2] 91 }

  condition:
    any of them
}