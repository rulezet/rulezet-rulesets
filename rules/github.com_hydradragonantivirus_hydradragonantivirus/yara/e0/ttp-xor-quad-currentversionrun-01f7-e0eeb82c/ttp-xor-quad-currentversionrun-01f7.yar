rule TTP_XOR_QUAD_CurrentVersionRun_01f7 {
  strings:
    $key_01f7 = { 52 98 [2] 76 96 [2] 5d ba [2] 73 98 [2] 67 83 [2] 68 99 [2] 76 84 [2] 74 85 [2] 6f 83 [2] 73 84 [2] 6f ab }

  condition:
    any of them
}