rule TTP_XOR_MULT_DOSStub_a2af {
  strings:
    $key_a2af = { f6 c7 [2] 82 df [2] c5 dd [2] 82 cc [2] cc c0 [2] c0 ca [2] d7 c1 [2] cc 8f [2] f1 }

  condition:
    any of them
}