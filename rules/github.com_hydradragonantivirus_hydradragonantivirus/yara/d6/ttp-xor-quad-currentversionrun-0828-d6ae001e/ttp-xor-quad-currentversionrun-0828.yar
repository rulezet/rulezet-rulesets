rule TTP_XOR_QUAD_CurrentVersionRun_0828 {
  strings:
    $key_0828 = { 5b 47 [2] 7f 49 [2] 54 65 [2] 7a 47 [2] 6e 5c [2] 61 46 [2] 7f 5b [2] 7d 5a [2] 66 5c [2] 7a 5b [2] 66 74 }

  condition:
    any of them
}