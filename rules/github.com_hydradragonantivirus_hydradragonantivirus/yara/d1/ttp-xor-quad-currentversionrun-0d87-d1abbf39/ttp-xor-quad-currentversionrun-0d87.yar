rule TTP_XOR_QUAD_CurrentVersionRun_0d87 {
  strings:
    $key_0d87 = { 5e e8 [2] 7a e6 [2] 51 ca [2] 7f e8 [2] 6b f3 [2] 64 e9 [2] 7a f4 [2] 78 f5 [2] 63 f3 [2] 7f f4 [2] 63 db }

  condition:
    any of them
}