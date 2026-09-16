rule TTP_XOR_QUAD_CurrentVersionRun_260a {
  strings:
    $key_260a = { 75 65 [2] 51 6b [2] 7a 47 [2] 54 65 [2] 40 7e [2] 4f 64 [2] 51 79 [2] 53 78 [2] 48 7e [2] 54 79 [2] 48 56 }

  condition:
    any of them
}