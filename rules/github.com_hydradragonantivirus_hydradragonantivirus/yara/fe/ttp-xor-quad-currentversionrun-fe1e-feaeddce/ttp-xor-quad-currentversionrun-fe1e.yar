rule TTP_XOR_QUAD_CurrentVersionRun_fe1e {
  strings:
    $key_fe1e = { ad 71 [2] 89 7f [2] a2 53 [2] 8c 71 [2] 98 6a [2] 97 70 [2] 89 6d [2] 8b 6c [2] 90 6a [2] 8c 6d [2] 90 42 }

  condition:
    any of them
}