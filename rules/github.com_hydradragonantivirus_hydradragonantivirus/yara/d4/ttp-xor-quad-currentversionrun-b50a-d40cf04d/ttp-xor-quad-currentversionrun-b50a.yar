rule TTP_XOR_QUAD_CurrentVersionRun_b50a {
  strings:
    $key_b50a = { e6 65 [2] c2 6b [2] e9 47 [2] c7 65 [2] d3 7e [2] dc 64 [2] c2 79 [2] c0 78 [2] db 7e [2] c7 79 [2] db 56 }

  condition:
    any of them
}