rule TTP_XOR_MULT_DOSStub_369d {
  strings:
    $key_369d = { 62 f5 [2] 16 ed [2] 51 ef [2] 16 fe [2] 58 f2 [2] 54 f8 [2] 43 f3 [2] 58 bd [2] 65 }

  condition:
    any of them
}