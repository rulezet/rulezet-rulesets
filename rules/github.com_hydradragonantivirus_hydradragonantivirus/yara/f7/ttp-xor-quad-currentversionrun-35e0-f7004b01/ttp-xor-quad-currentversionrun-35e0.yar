rule TTP_XOR_QUAD_CurrentVersionRun_35e0 {
  strings:
    $key_35e0 = { 66 8f [2] 42 81 [2] 69 ad [2] 47 8f [2] 53 94 [2] 5c 8e [2] 42 93 [2] 40 92 [2] 5b 94 [2] 47 93 [2] 5b bc }

  condition:
    any of them
}