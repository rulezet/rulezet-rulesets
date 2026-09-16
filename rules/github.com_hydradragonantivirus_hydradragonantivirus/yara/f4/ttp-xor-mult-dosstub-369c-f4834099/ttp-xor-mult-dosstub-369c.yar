rule TTP_XOR_MULT_DOSStub_369c {
  strings:
    $key_369c = { 62 f4 [2] 16 ec [2] 51 ee [2] 16 ff [2] 58 f3 [2] 54 f9 [2] 43 f2 [2] 58 bc [2] 65 }

  condition:
    any of them
}