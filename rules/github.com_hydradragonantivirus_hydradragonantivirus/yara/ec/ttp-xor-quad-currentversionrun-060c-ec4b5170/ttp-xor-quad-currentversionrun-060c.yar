rule TTP_XOR_QUAD_CurrentVersionRun_060c {
  strings:
    $key_060c = { 55 63 [2] 71 6d [2] 5a 41 [2] 74 63 [2] 60 78 [2] 6f 62 [2] 71 7f [2] 73 7e [2] 68 78 [2] 74 7f [2] 68 50 }

  condition:
    any of them
}