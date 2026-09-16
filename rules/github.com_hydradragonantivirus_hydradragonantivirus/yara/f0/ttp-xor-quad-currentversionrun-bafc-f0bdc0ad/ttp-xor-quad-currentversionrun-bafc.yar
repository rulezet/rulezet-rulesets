rule TTP_XOR_QUAD_CurrentVersionRun_bafc {
  strings:
    $key_bafc = { e9 93 [2] cd 9d [2] e6 b1 [2] c8 93 [2] dc 88 [2] d3 92 [2] cd 8f [2] cf 8e [2] d4 88 [2] c8 8f [2] d4 a0 }

  condition:
    any of them
}