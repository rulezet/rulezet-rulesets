rule TTP_XOR_QUAD_CurrentVersionRun_fde0 {
  strings:
    $key_fde0 = { ae 8f [2] 8a 81 [2] a1 ad [2] 8f 8f [2] 9b 94 [2] 94 8e [2] 8a 93 [2] 88 92 [2] 93 94 [2] 8f 93 [2] 93 bc }

  condition:
    any of them
}