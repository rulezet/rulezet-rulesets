rule TTP_XOR_QUAD_CurrentVersionRun_fad9 {
  strings:
    $key_fad9 = { a9 b6 [2] 8d b8 [2] a6 94 [2] 88 b6 [2] 9c ad [2] 93 b7 [2] 8d aa [2] 8f ab [2] 94 ad [2] 88 aa [2] 94 85 }

  condition:
    any of them
}