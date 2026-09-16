rule TTP_XOR_QUAD_CurrentVersionRun_6ad9 {
  strings:
    $key_6ad9 = { 39 b6 [2] 1d b8 [2] 36 94 [2] 18 b6 [2] 0c ad [2] 03 b7 [2] 1d aa [2] 1f ab [2] 04 ad [2] 18 aa [2] 04 85 }

  condition:
    any of them
}