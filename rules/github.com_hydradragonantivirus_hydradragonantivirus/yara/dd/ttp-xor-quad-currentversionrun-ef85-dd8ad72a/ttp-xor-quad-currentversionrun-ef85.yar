rule TTP_XOR_QUAD_CurrentVersionRun_ef85 {
  strings:
    $key_ef85 = { bc ea [2] 98 e4 [2] b3 c8 [2] 9d ea [2] 89 f1 [2] 86 eb [2] 98 f6 [2] 9a f7 [2] 81 f1 [2] 9d f6 [2] 81 d9 }

  condition:
    any of them
}