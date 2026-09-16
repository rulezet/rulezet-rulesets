rule TTP_XOR_QUAD_CurrentVersionRun_3f2f {
  strings:
    $key_3f2f = { 6c 40 [2] 48 4e [2] 63 62 [2] 4d 40 [2] 59 5b [2] 56 41 [2] 48 5c [2] 4a 5d [2] 51 5b [2] 4d 5c [2] 51 73 }

  condition:
    any of them
}