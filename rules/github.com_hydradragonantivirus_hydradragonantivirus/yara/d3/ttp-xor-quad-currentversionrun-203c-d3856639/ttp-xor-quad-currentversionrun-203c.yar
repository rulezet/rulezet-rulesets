rule TTP_XOR_QUAD_CurrentVersionRun_203c {
  strings:
    $key_203c = { 73 53 [2] 57 5d [2] 7c 71 [2] 52 53 [2] 46 48 [2] 49 52 [2] 57 4f [2] 55 4e [2] 4e 48 [2] 52 4f [2] 4e 60 }

  condition:
    any of them
}