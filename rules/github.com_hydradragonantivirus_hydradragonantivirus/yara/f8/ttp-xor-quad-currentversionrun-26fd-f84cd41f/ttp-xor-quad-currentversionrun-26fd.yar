rule TTP_XOR_QUAD_CurrentVersionRun_26fd {
  strings:
    $key_26fd = { 75 92 [2] 51 9c [2] 7a b0 [2] 54 92 [2] 40 89 [2] 4f 93 [2] 51 8e [2] 53 8f [2] 48 89 [2] 54 8e [2] 48 a1 }

  condition:
    any of them
}