rule TTP_XOR_QUAD_CurrentVersionRun_333e {
  strings:
    $key_333e = { 60 51 [2] 44 5f [2] 6f 73 [2] 41 51 [2] 55 4a [2] 5a 50 [2] 44 4d [2] 46 4c [2] 5d 4a [2] 41 4d [2] 5d 62 }

  condition:
    any of them
}