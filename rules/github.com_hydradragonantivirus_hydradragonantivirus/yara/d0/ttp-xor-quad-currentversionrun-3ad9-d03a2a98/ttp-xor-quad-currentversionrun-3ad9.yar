rule TTP_XOR_QUAD_CurrentVersionRun_3ad9 {
  strings:
    $key_3ad9 = { 69 b6 [2] 4d b8 [2] 66 94 [2] 48 b6 [2] 5c ad [2] 53 b7 [2] 4d aa [2] 4f ab [2] 54 ad [2] 48 aa [2] 54 85 }

  condition:
    any of them
}