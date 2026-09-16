rule TTP_XOR_QUAD_CurrentVersionRun_bec4 {
  strings:
    $key_bec4 = { ed ab [2] c9 a5 [2] e2 89 [2] cc ab [2] d8 b0 [2] d7 aa [2] c9 b7 [2] cb b6 [2] d0 b0 [2] cc b7 [2] d0 98 }

  condition:
    any of them
}