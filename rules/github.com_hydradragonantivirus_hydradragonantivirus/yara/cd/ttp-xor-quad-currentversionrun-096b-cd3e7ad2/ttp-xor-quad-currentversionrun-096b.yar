rule TTP_XOR_QUAD_CurrentVersionRun_096b {
  strings:
    $key_096b = { 5a 04 [2] 7e 0a [2] 55 26 [2] 7b 04 [2] 6f 1f [2] 60 05 [2] 7e 18 [2] 7c 19 [2] 67 1f [2] 7b 18 [2] 67 37 }

  condition:
    any of them
}