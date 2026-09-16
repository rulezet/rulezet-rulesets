rule TTP_XOR_QUAD_CurrentVersionRun_3be0 {
  strings:
    $key_3be0 = { 68 8f [2] 4c 81 [2] 67 ad [2] 49 8f [2] 5d 94 [2] 52 8e [2] 4c 93 [2] 4e 92 [2] 55 94 [2] 49 93 [2] 55 bc }

  condition:
    any of them
}