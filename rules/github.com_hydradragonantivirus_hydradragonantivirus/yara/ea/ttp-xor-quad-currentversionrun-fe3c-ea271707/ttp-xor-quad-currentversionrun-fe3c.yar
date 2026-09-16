rule TTP_XOR_QUAD_CurrentVersionRun_fe3c {
  strings:
    $key_fe3c = { ad 53 [2] 89 5d [2] a2 71 [2] 8c 53 [2] 98 48 [2] 97 52 [2] 89 4f [2] 8b 4e [2] 90 48 [2] 8c 4f [2] 90 60 }

  condition:
    any of them
}