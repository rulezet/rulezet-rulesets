rule TTP_XOR_MULT_DOSStub_96ba {
  strings:
    $key_96ba = { c2 d2 [2] b6 ca [2] f1 c8 [2] b6 d9 [2] f8 d5 [2] f4 df [2] e3 d4 [2] f8 9a [2] c5 }

  condition:
    any of them
}