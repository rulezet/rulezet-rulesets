rule TTP_XOR_QUAD_CurrentVersionRun_b2e5 {
  strings:
    $key_b2e5 = { e1 8a [2] c5 84 [2] ee a8 [2] c0 8a [2] d4 91 [2] db 8b [2] c5 96 [2] c7 97 [2] dc 91 [2] c0 96 [2] dc b9 }

  condition:
    any of them
}