rule TTP_XOR_QUAD_CurrentVersionRun_ef3e {
  strings:
    $key_ef3e = { bc 51 [2] 98 5f [2] b3 73 [2] 9d 51 [2] 89 4a [2] 86 50 [2] 98 4d [2] 9a 4c [2] 81 4a [2] 9d 4d [2] 81 62 }

  condition:
    any of them
}