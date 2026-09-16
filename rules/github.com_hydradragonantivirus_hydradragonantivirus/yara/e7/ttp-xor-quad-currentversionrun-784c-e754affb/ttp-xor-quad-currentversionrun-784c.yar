rule TTP_XOR_QUAD_CurrentVersionRun_784c {
  strings:
    $key_784c = { 2b 23 [2] 0f 2d [2] 24 01 [2] 0a 23 [2] 1e 38 [2] 11 22 [2] 0f 3f [2] 0d 3e [2] 16 38 [2] 0a 3f [2] 16 10 }

  condition:
    any of them
}