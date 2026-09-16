rule TTP_XOR_QUAD_CurrentVersionRun_202b {
  strings:
    $key_202b = { 73 44 [2] 57 4a [2] 7c 66 [2] 52 44 [2] 46 5f [2] 49 45 [2] 57 58 [2] 55 59 [2] 4e 5f [2] 52 58 [2] 4e 77 }

  condition:
    any of them
}