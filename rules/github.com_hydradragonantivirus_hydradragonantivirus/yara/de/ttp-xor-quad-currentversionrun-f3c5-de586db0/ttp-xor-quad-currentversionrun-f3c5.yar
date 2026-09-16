rule TTP_XOR_QUAD_CurrentVersionRun_f3c5 {
  strings:
    $key_f3c5 = { a0 aa [2] 84 a4 [2] af 88 [2] 81 aa [2] 95 b1 [2] 9a ab [2] 84 b6 [2] 86 b7 [2] 9d b1 [2] 81 b6 [2] 9d 99 }

  condition:
    any of them
}