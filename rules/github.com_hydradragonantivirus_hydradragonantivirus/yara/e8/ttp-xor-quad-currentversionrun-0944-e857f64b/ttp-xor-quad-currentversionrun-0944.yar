rule TTP_XOR_QUAD_CurrentVersionRun_0944 {
  strings:
    $key_0944 = { 5a 2b [2] 7e 25 [2] 55 09 [2] 7b 2b [2] 6f 30 [2] 60 2a [2] 7e 37 [2] 7c 36 [2] 67 30 [2] 7b 37 [2] 67 18 }

  condition:
    any of them
}