rule TTP_XOR_QUAD_CurrentVersionRun_e5fd {
  strings:
    $key_e5fd = { b6 92 [2] 92 9c [2] b9 b0 [2] 97 92 [2] 83 89 [2] 8c 93 [2] 92 8e [2] 90 8f [2] 8b 89 [2] 97 8e [2] 8b a1 }

  condition:
    any of them
}