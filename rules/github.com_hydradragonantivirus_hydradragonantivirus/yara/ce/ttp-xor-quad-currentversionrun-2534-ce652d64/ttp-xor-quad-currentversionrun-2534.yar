rule TTP_XOR_QUAD_CurrentVersionRun_2534 {
  strings:
    $key_2534 = { 76 5b [2] 52 55 [2] 79 79 [2] 57 5b [2] 43 40 [2] 4c 5a [2] 52 47 [2] 50 46 [2] 4b 40 [2] 57 47 [2] 4b 68 }

  condition:
    any of them
}