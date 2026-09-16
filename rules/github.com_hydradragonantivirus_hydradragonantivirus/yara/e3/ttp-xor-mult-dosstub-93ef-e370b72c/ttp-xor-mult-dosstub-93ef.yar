rule TTP_XOR_MULT_DOSStub_93ef {
  strings:
    $key_93ef = { c7 87 [2] b3 9f [2] f4 9d [2] b3 8c [2] fd 80 [2] f1 8a [2] e6 81 [2] fd cf [2] c0 }

  condition:
    any of them
}