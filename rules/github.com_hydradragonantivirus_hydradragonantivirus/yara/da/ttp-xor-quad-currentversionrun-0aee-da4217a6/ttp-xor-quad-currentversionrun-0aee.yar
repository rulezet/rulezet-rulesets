rule TTP_XOR_QUAD_CurrentVersionRun_0aee {
  strings:
    $key_0aee = { 59 81 [2] 7d 8f [2] 56 a3 [2] 78 81 [2] 6c 9a [2] 63 80 [2] 7d 9d [2] 7f 9c [2] 64 9a [2] 78 9d [2] 64 b2 }

  condition:
    any of them
}