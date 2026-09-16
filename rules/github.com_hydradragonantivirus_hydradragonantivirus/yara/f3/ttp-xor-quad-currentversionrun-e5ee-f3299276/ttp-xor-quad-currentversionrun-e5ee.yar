rule TTP_XOR_QUAD_CurrentVersionRun_e5ee {
  strings:
    $key_e5ee = { b6 81 [2] 92 8f [2] b9 a3 [2] 97 81 [2] 83 9a [2] 8c 80 [2] 92 9d [2] 90 9c [2] 8b 9a [2] 97 9d [2] 8b b2 }

  condition:
    any of them
}