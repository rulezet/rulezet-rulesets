rule TTP_XOR_MULT_DOSStub_eaac {
  strings:
    $key_eaac = { be c4 [2] ca dc [2] 8d de [2] ca cf [2] 84 c3 [2] 88 c9 [2] 9f c2 [2] 84 8c [2] b9 }

  condition:
    any of them
}