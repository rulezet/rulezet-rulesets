rule TTP_XOR_QUAD_CurrentVersionRun_d8a3 {
  strings:
    $key_d8a3 = { 8b cc [2] af c2 [2] 84 ee [2] aa cc [2] be d7 [2] b1 cd [2] af d0 [2] ad d1 [2] b6 d7 [2] aa d0 [2] b6 ff }

  condition:
    any of them
}