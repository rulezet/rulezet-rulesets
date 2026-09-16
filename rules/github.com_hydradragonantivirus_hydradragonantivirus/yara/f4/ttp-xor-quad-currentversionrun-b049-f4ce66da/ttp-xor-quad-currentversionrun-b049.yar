rule TTP_XOR_QUAD_CurrentVersionRun_b049 {
  strings:
    $key_b049 = { e3 26 [2] c7 28 [2] ec 04 [2] c2 26 [2] d6 3d [2] d9 27 [2] c7 3a [2] c5 3b [2] de 3d [2] c2 3a [2] de 15 }

  condition:
    any of them
}