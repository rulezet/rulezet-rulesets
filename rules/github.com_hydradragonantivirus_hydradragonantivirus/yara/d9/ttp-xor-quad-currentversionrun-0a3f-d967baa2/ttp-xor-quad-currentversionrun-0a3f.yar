rule TTP_XOR_QUAD_CurrentVersionRun_0a3f {
  strings:
    $key_0a3f = { 59 50 [2] 7d 5e [2] 56 72 [2] 78 50 [2] 6c 4b [2] 63 51 [2] 7d 4c [2] 7f 4d [2] 64 4b [2] 78 4c [2] 64 63 }

  condition:
    any of them
}