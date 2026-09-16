rule TTP_XOR_MULT_DOSStub_d026 {
  strings:
    $key_d026 = { 84 4e [2] f0 56 [2] b7 54 [2] f0 45 [2] be 49 [2] b2 43 [2] a5 48 [2] be 06 [2] 83 }

  condition:
    any of them
}