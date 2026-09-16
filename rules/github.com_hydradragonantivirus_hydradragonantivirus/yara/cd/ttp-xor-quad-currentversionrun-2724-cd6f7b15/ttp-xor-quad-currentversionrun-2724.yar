rule TTP_XOR_QUAD_CurrentVersionRun_2724 {
  strings:
    $key_2724 = { 74 4b [2] 50 45 [2] 7b 69 [2] 55 4b [2] 41 50 [2] 4e 4a [2] 50 57 [2] 52 56 [2] 49 50 [2] 55 57 [2] 49 78 }

  condition:
    any of them
}