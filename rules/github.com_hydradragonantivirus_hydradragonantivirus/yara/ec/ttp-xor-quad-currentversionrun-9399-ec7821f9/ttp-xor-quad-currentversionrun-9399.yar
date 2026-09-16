rule TTP_XOR_QUAD_CurrentVersionRun_9399 {
  strings:
    $key_9399 = { c0 f6 [2] e4 f8 [2] cf d4 [2] e1 f6 [2] f5 ed [2] fa f7 [2] e4 ea [2] e6 eb [2] fd ed [2] e1 ea [2] fd c5 }

  condition:
    any of them
}