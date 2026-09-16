rule TTP_XOR_QUAD_CurrentVersionRun_3738 {
  strings:
    $key_3738 = { 64 57 [2] 40 59 [2] 6b 75 [2] 45 57 [2] 51 4c [2] 5e 56 [2] 40 4b [2] 42 4a [2] 59 4c [2] 45 4b [2] 59 64 }

  condition:
    any of them
}