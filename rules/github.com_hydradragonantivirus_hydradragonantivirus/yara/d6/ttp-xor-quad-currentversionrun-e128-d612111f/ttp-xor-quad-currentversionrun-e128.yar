rule TTP_XOR_QUAD_CurrentVersionRun_e128 {
  strings:
    $key_e128 = { b2 47 [2] 96 49 [2] bd 65 [2] 93 47 [2] 87 5c [2] 88 46 [2] 96 5b [2] 94 5a [2] 8f 5c [2] 93 5b [2] 8f 74 }

  condition:
    any of them
}