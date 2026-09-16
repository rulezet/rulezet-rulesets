rule TTP_XOR_QUAD_CurrentVersionRun_b5fc {
  strings:
    $key_b5fc = { e6 93 [2] c2 9d [2] e9 b1 [2] c7 93 [2] d3 88 [2] dc 92 [2] c2 8f [2] c0 8e [2] db 88 [2] c7 8f [2] db a0 }

  condition:
    any of them
}