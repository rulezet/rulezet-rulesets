rule TTP_XOR_QUAD_CurrentVersionRun_00dc {
  strings:
    $key_00dc = { 53 b3 [2] 77 bd [2] 5c 91 [2] 72 b3 [2] 66 a8 [2] 69 b2 [2] 77 af [2] 75 ae [2] 6e a8 [2] 72 af [2] 6e 80 }

  condition:
    any of them
}