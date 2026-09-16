rule TTP_XOR_QUAD_CurrentVersionRun_789d {
  strings:
    $key_789d = { 2b f2 [2] 0f fc [2] 24 d0 [2] 0a f2 [2] 1e e9 [2] 11 f3 [2] 0f ee [2] 0d ef [2] 16 e9 [2] 0a ee [2] 16 c1 }

  condition:
    any of them
}