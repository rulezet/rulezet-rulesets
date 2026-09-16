rule TTP_XOR_QUAD_CurrentVersionRun_fe4f {
  strings:
    $key_fe4f = { ad 20 [2] 89 2e [2] a2 02 [2] 8c 20 [2] 98 3b [2] 97 21 [2] 89 3c [2] 8b 3d [2] 90 3b [2] 8c 3c [2] 90 13 }

  condition:
    any of them
}