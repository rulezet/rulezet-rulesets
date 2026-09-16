rule TTP_XOR_QUAD_CurrentVersionRun_0738 {
  strings:
    $key_0738 = { 54 57 [2] 70 59 [2] 5b 75 [2] 75 57 [2] 61 4c [2] 6e 56 [2] 70 4b [2] 72 4a [2] 69 4c [2] 75 4b [2] 69 64 }

  condition:
    any of them
}