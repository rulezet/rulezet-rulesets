rule TTP_XOR_QUAD_CurrentVersionRun_9cdc {
  strings:
    $key_9cdc = { cf b3 [2] eb bd [2] c0 91 [2] ee b3 [2] fa a8 [2] f5 b2 [2] eb af [2] e9 ae [2] f2 a8 [2] ee af [2] f2 80 }

  condition:
    any of them
}