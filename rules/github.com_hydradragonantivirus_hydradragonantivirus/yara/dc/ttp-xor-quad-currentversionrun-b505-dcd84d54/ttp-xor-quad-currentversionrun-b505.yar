rule TTP_XOR_QUAD_CurrentVersionRun_b505 {
  strings:
    $key_b505 = { e6 6a [2] c2 64 [2] e9 48 [2] c7 6a [2] d3 71 [2] dc 6b [2] c2 76 [2] c0 77 [2] db 71 [2] c7 76 [2] db 59 }

  condition:
    any of them
}