rule TTP_XOR_QUAD_CurrentVersionRun_0928 {
  strings:
    $key_0928 = { 5a 47 [2] 7e 49 [2] 55 65 [2] 7b 47 [2] 6f 5c [2] 60 46 [2] 7e 5b [2] 7c 5a [2] 67 5c [2] 7b 5b [2] 67 74 }

  condition:
    any of them
}