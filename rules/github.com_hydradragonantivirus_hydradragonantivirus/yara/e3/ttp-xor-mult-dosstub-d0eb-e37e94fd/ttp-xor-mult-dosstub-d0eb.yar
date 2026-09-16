rule TTP_XOR_MULT_DOSStub_d0eb {
  strings:
    $key_d0eb = { 84 83 [2] f0 9b [2] b7 99 [2] f0 88 [2] be 84 [2] b2 8e [2] a5 85 [2] be cb [2] 83 }

  condition:
    any of them
}