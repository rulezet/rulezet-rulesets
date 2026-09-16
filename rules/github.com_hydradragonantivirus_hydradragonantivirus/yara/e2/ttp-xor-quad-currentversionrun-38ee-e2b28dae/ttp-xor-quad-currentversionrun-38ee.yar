rule TTP_XOR_QUAD_CurrentVersionRun_38ee {
  strings:
    $key_38ee = { 6b 81 [2] 4f 8f [2] 64 a3 [2] 4a 81 [2] 5e 9a [2] 51 80 [2] 4f 9d [2] 4d 9c [2] 56 9a [2] 4a 9d [2] 56 b2 }

  condition:
    any of them
}