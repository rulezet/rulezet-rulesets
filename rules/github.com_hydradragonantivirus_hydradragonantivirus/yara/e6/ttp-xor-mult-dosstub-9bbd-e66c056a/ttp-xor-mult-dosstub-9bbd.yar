rule TTP_XOR_MULT_DOSStub_9bbd {
  strings:
    $key_9bbd = { cf d5 [2] bb cd [2] fc cf [2] bb de [2] f5 d2 [2] f9 d8 [2] ee d3 [2] f5 9d [2] c8 }

  condition:
    any of them
}