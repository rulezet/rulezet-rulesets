rule TTP_XOR_QUAD_CurrentVersionRun_ffd9 {
  strings:
    $key_ffd9 = { ac b6 [2] 88 b8 [2] a3 94 [2] 8d b6 [2] 99 ad [2] 96 b7 [2] 88 aa [2] 8a ab [2] 91 ad [2] 8d aa [2] 91 85 }

  condition:
    any of them
}