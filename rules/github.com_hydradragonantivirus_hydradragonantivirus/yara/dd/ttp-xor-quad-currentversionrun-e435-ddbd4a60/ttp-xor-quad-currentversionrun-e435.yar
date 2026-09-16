rule TTP_XOR_QUAD_CurrentVersionRun_e435 {
  strings:
    $key_e435 = { b7 5a [2] 93 54 [2] b8 78 [2] 96 5a [2] 82 41 [2] 8d 5b [2] 93 46 [2] 91 47 [2] 8a 41 [2] 96 46 [2] 8a 69 }

  condition:
    any of them
}