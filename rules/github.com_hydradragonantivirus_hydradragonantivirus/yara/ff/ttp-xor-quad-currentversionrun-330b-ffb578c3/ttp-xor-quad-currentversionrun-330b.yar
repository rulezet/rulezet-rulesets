rule TTP_XOR_QUAD_CurrentVersionRun_330b {
  strings:
    $key_330b = { 60 64 [2] 44 6a [2] 6f 46 [2] 41 64 [2] 55 7f [2] 5a 65 [2] 44 78 [2] 46 79 [2] 5d 7f [2] 41 78 [2] 5d 57 }

  condition:
    any of them
}