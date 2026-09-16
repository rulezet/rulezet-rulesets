rule TTP_XOR_QUAD_CurrentVersionRun_3dfc {
  strings:
    $key_3dfc = { 6e 93 [2] 4a 9d [2] 61 b1 [2] 4f 93 [2] 5b 88 [2] 54 92 [2] 4a 8f [2] 48 8e [2] 53 88 [2] 4f 8f [2] 53 a0 }

  condition:
    any of them
}