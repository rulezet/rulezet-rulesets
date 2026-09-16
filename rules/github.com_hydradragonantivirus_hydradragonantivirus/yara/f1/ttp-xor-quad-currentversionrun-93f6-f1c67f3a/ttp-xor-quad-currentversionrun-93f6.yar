rule TTP_XOR_QUAD_CurrentVersionRun_93f6 {
  strings:
    $key_93f6 = { c0 99 [2] e4 97 [2] cf bb [2] e1 99 [2] f5 82 [2] fa 98 [2] e4 85 [2] e6 84 [2] fd 82 [2] e1 85 [2] fd aa }

  condition:
    any of them
}