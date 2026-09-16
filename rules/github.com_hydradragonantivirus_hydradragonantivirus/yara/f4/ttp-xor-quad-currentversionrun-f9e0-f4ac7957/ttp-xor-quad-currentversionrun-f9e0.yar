rule TTP_XOR_QUAD_CurrentVersionRun_f9e0 {
  strings:
    $key_f9e0 = { aa 8f [2] 8e 81 [2] a5 ad [2] 8b 8f [2] 9f 94 [2] 90 8e [2] 8e 93 [2] 8c 92 [2] 97 94 [2] 8b 93 [2] 97 bc }

  condition:
    any of them
}