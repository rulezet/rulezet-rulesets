rule TTP_XOR_QUAD_CurrentVersionRun_30dc {
  strings:
    $key_30dc = { 63 b3 [2] 47 bd [2] 6c 91 [2] 42 b3 [2] 56 a8 [2] 59 b2 [2] 47 af [2] 45 ae [2] 5e a8 [2] 42 af [2] 5e 80 }

  condition:
    any of them
}