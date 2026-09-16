rule TTP_XOR_MULT_DOSStub_91af {
  strings:
    $key_91af = { c5 c7 [2] b1 df [2] f6 dd [2] b1 cc [2] ff c0 [2] f3 ca [2] e4 c1 [2] ff 8f [2] c2 }

  condition:
    any of them
}