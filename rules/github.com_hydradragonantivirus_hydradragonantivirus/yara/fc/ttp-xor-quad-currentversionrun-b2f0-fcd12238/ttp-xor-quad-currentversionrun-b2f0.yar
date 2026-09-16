rule TTP_XOR_QUAD_CurrentVersionRun_b2f0 {
  strings:
    $key_b2f0 = { e1 9f [2] c5 91 [2] ee bd [2] c0 9f [2] d4 84 [2] db 9e [2] c5 83 [2] c7 82 [2] dc 84 [2] c0 83 [2] dc ac }

  condition:
    any of them
}