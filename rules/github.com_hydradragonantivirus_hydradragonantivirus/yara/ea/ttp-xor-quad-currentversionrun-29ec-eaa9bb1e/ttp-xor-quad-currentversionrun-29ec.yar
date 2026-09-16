rule TTP_XOR_QUAD_CurrentVersionRun_29ec {
  strings:
    $key_29ec = { 7a 83 [2] 5e 8d [2] 75 a1 [2] 5b 83 [2] 4f 98 [2] 40 82 [2] 5e 9f [2] 5c 9e [2] 47 98 [2] 5b 9f [2] 47 b0 }

  condition:
    any of them
}