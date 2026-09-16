rule TTP_XOR_MULT_DOSStub_8faf {
  strings:
    $key_8faf = { db c7 [2] af df [2] e8 dd [2] af cc [2] e1 c0 [2] ed ca [2] fa c1 [2] e1 8f [2] dc }

  condition:
    any of them
}