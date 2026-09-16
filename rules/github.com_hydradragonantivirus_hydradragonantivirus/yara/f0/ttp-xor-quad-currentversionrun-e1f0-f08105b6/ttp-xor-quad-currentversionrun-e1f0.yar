rule TTP_XOR_QUAD_CurrentVersionRun_e1f0 {
  strings:
    $key_e1f0 = { b2 9f [2] 96 91 [2] bd bd [2] 93 9f [2] 87 84 [2] 88 9e [2] 96 83 [2] 94 82 [2] 8f 84 [2] 93 83 [2] 8f ac }

  condition:
    any of them
}