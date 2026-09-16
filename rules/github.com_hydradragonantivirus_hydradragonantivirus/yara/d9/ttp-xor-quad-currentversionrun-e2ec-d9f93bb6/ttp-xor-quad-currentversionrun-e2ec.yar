rule TTP_XOR_QUAD_CurrentVersionRun_e2ec {
  strings:
    $key_e2ec = { b1 83 [2] 95 8d [2] be a1 [2] 90 83 [2] 84 98 [2] 8b 82 [2] 95 9f [2] 97 9e [2] 8c 98 [2] 90 9f [2] 8c b0 }

  condition:
    any of them
}