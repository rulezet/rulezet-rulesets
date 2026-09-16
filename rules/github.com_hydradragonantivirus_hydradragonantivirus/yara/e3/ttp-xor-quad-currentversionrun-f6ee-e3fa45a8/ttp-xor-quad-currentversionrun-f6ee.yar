rule TTP_XOR_QUAD_CurrentVersionRun_f6ee {
  strings:
    $key_f6ee = { a5 81 [2] 81 8f [2] aa a3 [2] 84 81 [2] 90 9a [2] 9f 80 [2] 81 9d [2] 83 9c [2] 98 9a [2] 84 9d [2] 98 b2 }

  condition:
    any of them
}