rule TTP_XOR_QUAD_CurrentVersionRun_130d {
  strings:
    $key_130d = { 40 62 [2] 64 6c [2] 4f 40 [2] 61 62 [2] 75 79 [2] 7a 63 [2] 64 7e [2] 66 7f [2] 7d 79 [2] 61 7e [2] 7d 51 }

  condition:
    any of them
}