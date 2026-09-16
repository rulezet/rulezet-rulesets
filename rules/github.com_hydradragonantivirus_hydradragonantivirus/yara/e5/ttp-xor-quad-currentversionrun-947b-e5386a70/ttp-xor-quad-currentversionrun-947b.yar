rule TTP_XOR_QUAD_CurrentVersionRun_947b {
  strings:
    $key_947b = { c7 14 [2] e3 1a [2] c8 36 [2] e6 14 [2] f2 0f [2] fd 15 [2] e3 08 [2] e1 09 [2] fa 0f [2] e6 08 [2] fa 27 }

  condition:
    any of them
}