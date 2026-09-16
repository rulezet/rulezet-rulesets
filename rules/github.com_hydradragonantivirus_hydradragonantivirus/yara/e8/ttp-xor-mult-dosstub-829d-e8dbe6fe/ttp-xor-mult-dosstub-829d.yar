rule TTP_XOR_MULT_DOSStub_829d {
  strings:
    $key_829d = { d6 f5 [2] a2 ed [2] e5 ef [2] a2 fe [2] ec f2 [2] e0 f8 [2] f7 f3 [2] ec bd [2] d1 }

  condition:
    any of them
}