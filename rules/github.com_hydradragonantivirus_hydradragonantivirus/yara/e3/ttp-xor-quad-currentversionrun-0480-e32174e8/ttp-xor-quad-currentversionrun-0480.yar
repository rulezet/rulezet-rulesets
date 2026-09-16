rule TTP_XOR_QUAD_CurrentVersionRun_0480 {
  strings:
    $key_0480 = { 57 ef [2] 73 e1 [2] 58 cd [2] 76 ef [2] 62 f4 [2] 6d ee [2] 73 f3 [2] 71 f2 [2] 6a f4 [2] 76 f3 [2] 6a dc }

  condition:
    any of them
}