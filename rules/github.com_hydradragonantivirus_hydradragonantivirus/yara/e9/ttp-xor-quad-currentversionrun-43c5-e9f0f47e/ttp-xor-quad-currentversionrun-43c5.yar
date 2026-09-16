rule TTP_XOR_QUAD_CurrentVersionRun_43c5 {
  strings:
    $key_43c5 = { 10 aa [2] 34 a4 [2] 1f 88 [2] 31 aa [2] 25 b1 [2] 2a ab [2] 34 b6 [2] 36 b7 [2] 2d b1 [2] 31 b6 [2] 2d 99 }

  condition:
    any of them
}