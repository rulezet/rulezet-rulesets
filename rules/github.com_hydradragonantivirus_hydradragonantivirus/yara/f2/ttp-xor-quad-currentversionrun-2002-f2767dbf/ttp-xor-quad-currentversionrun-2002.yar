rule TTP_XOR_QUAD_CurrentVersionRun_2002 {
  strings:
    $key_2002 = { 73 6d [2] 57 63 [2] 7c 4f [2] 52 6d [2] 46 76 [2] 49 6c [2] 57 71 [2] 55 70 [2] 4e 76 [2] 52 71 [2] 4e 5e }

  condition:
    any of them
}