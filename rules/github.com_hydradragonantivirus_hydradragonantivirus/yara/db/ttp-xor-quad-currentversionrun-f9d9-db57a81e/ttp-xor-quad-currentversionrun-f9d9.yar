rule TTP_XOR_QUAD_CurrentVersionRun_f9d9 {
  strings:
    $key_f9d9 = { aa b6 [2] 8e b8 [2] a5 94 [2] 8b b6 [2] 9f ad [2] 90 b7 [2] 8e aa [2] 8c ab [2] 97 ad [2] 8b aa [2] 97 85 }

  condition:
    any of them
}