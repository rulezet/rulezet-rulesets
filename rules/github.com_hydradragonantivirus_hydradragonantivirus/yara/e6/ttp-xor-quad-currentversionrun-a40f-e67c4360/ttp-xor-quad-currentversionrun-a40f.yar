rule TTP_XOR_QUAD_CurrentVersionRun_a40f {
  strings:
    $key_a40f = { f7 60 [2] d3 6e [2] f8 42 [2] d6 60 [2] c2 7b [2] cd 61 [2] d3 7c [2] d1 7d [2] ca 7b [2] d6 7c [2] ca 53 }

  condition:
    any of them
}