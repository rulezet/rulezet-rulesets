rule TTP_XOR_QUAD_CurrentVersionRun_3bc5 {
  strings:
    $key_3bc5 = { 68 aa [2] 4c a4 [2] 67 88 [2] 49 aa [2] 5d b1 [2] 52 ab [2] 4c b6 [2] 4e b7 [2] 55 b1 [2] 49 b6 [2] 55 99 }

  condition:
    any of them
}