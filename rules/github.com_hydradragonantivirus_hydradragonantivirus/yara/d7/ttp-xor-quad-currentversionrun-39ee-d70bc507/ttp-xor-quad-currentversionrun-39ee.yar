rule TTP_XOR_QUAD_CurrentVersionRun_39ee {
  strings:
    $key_39ee = { 6a 81 [2] 4e 8f [2] 65 a3 [2] 4b 81 [2] 5f 9a [2] 50 80 [2] 4e 9d [2] 4c 9c [2] 57 9a [2] 4b 9d [2] 57 b2 }

  condition:
    any of them
}