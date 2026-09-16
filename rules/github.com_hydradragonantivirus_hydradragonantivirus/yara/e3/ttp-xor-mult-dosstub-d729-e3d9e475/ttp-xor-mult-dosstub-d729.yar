rule TTP_XOR_MULT_DOSStub_d729 {
  strings:
    $key_d729 = { 83 41 [2] f7 59 [2] b0 5b [2] f7 4a [2] b9 46 [2] b5 4c [2] a2 47 [2] b9 09 [2] 84 }

  condition:
    any of them
}