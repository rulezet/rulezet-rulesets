rule TTP_XOR_QUAD_CurrentVersionRun_29c4 {
  strings:
    $key_29c4 = { 7a ab [2] 5e a5 [2] 75 89 [2] 5b ab [2] 4f b0 [2] 40 aa [2] 5e b7 [2] 5c b6 [2] 47 b0 [2] 5b b7 [2] 47 98 }

  condition:
    any of them
}