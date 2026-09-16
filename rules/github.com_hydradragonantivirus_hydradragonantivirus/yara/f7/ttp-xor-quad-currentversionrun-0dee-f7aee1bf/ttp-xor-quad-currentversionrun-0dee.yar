rule TTP_XOR_QUAD_CurrentVersionRun_0dee {
  strings:
    $key_0dee = { 5e 81 [2] 7a 8f [2] 51 a3 [2] 7f 81 [2] 6b 9a [2] 64 80 [2] 7a 9d [2] 78 9c [2] 63 9a [2] 7f 9d [2] 63 b2 }

  condition:
    any of them
}