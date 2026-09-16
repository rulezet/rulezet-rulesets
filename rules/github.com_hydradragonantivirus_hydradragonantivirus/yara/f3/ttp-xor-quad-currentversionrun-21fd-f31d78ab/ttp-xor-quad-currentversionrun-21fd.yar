rule TTP_XOR_QUAD_CurrentVersionRun_21fd {
  strings:
    $key_21fd = { 72 92 [2] 56 9c [2] 7d b0 [2] 53 92 [2] 47 89 [2] 48 93 [2] 56 8e [2] 54 8f [2] 4f 89 [2] 53 8e [2] 4f a1 }

  condition:
    any of them
}