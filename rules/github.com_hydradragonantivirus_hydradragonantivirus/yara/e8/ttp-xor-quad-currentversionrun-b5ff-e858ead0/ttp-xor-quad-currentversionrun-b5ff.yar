rule TTP_XOR_QUAD_CurrentVersionRun_b5ff {
  strings:
    $key_b5ff = { e6 90 [2] c2 9e [2] e9 b2 [2] c7 90 [2] d3 8b [2] dc 91 [2] c2 8c [2] c0 8d [2] db 8b [2] c7 8c [2] db a3 }

  condition:
    any of them
}