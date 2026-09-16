rule TTP_XOR_QUAD_CurrentVersionRun_4480 {
  strings:
    $key_4480 = { 17 ef [2] 33 e1 [2] 18 cd [2] 36 ef [2] 22 f4 [2] 2d ee [2] 33 f3 [2] 31 f2 [2] 2a f4 [2] 36 f3 [2] 2a dc }

  condition:
    any of them
}