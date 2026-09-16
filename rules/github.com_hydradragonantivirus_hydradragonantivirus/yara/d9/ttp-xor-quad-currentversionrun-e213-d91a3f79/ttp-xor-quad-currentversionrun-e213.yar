rule TTP_XOR_QUAD_CurrentVersionRun_e213 {
  strings:
    $key_e213 = { b1 7c [2] 95 72 [2] be 5e [2] 90 7c [2] 84 67 [2] 8b 7d [2] 95 60 [2] 97 61 [2] 8c 67 [2] 90 60 [2] 8c 4f }

  condition:
    any of them
}