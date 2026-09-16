rule TTP_XOR_QUAD_CurrentVersionRun_939f {
  strings:
    $key_939f = { c0 f0 [2] e4 fe [2] cf d2 [2] e1 f0 [2] f5 eb [2] fa f1 [2] e4 ec [2] e6 ed [2] fd eb [2] e1 ec [2] fd c3 }

  condition:
    any of them
}