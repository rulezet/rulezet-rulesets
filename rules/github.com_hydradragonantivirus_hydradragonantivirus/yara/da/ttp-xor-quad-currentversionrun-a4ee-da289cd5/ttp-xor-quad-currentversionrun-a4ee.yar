rule TTP_XOR_QUAD_CurrentVersionRun_a4ee {
  strings:
    $key_a4ee = { f7 81 [2] d3 8f [2] f8 a3 [2] d6 81 [2] c2 9a [2] cd 80 [2] d3 9d [2] d1 9c [2] ca 9a [2] d6 9d [2] ca b2 }

  condition:
    any of them
}