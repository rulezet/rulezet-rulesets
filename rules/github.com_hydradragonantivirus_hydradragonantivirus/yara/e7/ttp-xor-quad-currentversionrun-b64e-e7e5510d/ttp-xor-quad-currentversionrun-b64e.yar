rule TTP_XOR_QUAD_CurrentVersionRun_b64e {
  strings:
    $key_b64e = { e5 21 [2] c1 2f [2] ea 03 [2] c4 21 [2] d0 3a [2] df 20 [2] c1 3d [2] c3 3c [2] d8 3a [2] c4 3d [2] d8 12 }

  condition:
    any of them
}