rule TTP_XOR_QUAD_CurrentVersionRun_30ec {
  strings:
    $key_30ec = { 63 83 [2] 47 8d [2] 6c a1 [2] 42 83 [2] 56 98 [2] 59 82 [2] 47 9f [2] 45 9e [2] 5e 98 [2] 42 9f [2] 5e b0 }

  condition:
    any of them
}