rule TTP_XOR_QUAD_CurrentVersionRun_bae9 {
  strings:
    $key_bae9 = { e9 86 [2] cd 88 [2] e6 a4 [2] c8 86 [2] dc 9d [2] d3 87 [2] cd 9a [2] cf 9b [2] d4 9d [2] c8 9a [2] d4 b5 }

  condition:
    any of them
}