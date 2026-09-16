rule TTP_XOR_QUAD_CurrentVersionRun_4cfc {
  strings:
    $key_4cfc = { 1f 93 [2] 3b 9d [2] 10 b1 [2] 3e 93 [2] 2a 88 [2] 25 92 [2] 3b 8f [2] 39 8e [2] 22 88 [2] 3e 8f [2] 22 a0 }

  condition:
    any of them
}