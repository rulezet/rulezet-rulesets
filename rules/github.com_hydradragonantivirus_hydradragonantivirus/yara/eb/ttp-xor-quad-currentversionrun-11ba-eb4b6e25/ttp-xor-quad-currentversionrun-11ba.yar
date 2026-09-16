rule TTP_XOR_QUAD_CurrentVersionRun_11ba {
  strings:
    $key_11ba = { 42 d5 [2] 66 db [2] 4d f7 [2] 63 d5 [2] 77 ce [2] 78 d4 [2] 66 c9 [2] 64 c8 [2] 7f ce [2] 63 c9 [2] 7f e6 }

  condition:
    any of them
}