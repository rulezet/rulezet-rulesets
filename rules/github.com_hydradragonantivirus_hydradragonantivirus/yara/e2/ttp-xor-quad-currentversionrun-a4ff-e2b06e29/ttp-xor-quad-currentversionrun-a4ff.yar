rule TTP_XOR_QUAD_CurrentVersionRun_a4ff {
  strings:
    $key_a4ff = { f7 90 [2] d3 9e [2] f8 b2 [2] d6 90 [2] c2 8b [2] cd 91 [2] d3 8c [2] d1 8d [2] ca 8b [2] d6 8c [2] ca a3 }

  condition:
    any of them
}