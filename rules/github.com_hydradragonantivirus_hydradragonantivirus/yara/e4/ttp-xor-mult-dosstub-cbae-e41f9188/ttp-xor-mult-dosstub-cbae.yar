rule TTP_XOR_MULT_DOSStub_cbae {
  strings:
    $key_cbae = { 9f c6 [2] eb de [2] ac dc [2] eb cd [2] a5 c1 [2] a9 cb [2] be c0 [2] a5 8e [2] 98 }

  condition:
    any of them
}