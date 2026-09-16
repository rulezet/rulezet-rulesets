rule TTP_XOR_MULT_DOSStub_9315 {
  strings:
    $key_9315 = { c7 7d [2] b3 65 [2] f4 67 [2] b3 76 [2] fd 7a [2] f1 70 [2] e6 7b [2] fd 35 [2] c0 }

  condition:
    any of them
}