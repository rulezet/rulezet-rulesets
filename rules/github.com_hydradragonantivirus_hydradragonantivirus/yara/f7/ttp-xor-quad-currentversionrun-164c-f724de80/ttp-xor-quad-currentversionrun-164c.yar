rule TTP_XOR_QUAD_CurrentVersionRun_164c {
  strings:
    $key_164c = { 45 23 [2] 61 2d [2] 4a 01 [2] 64 23 [2] 70 38 [2] 7f 22 [2] 61 3f [2] 63 3e [2] 78 38 [2] 64 3f [2] 78 10 }

  condition:
    any of them
}