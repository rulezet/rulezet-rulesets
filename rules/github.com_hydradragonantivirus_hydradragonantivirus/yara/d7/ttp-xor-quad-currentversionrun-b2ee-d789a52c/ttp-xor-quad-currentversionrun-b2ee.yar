rule TTP_XOR_QUAD_CurrentVersionRun_b2ee {
  strings:
    $key_b2ee = { e1 81 [2] c5 8f [2] ee a3 [2] c0 81 [2] d4 9a [2] db 80 [2] c5 9d [2] c7 9c [2] dc 9a [2] c0 9d [2] dc b2 }

  condition:
    any of them
}