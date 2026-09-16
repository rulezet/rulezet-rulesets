rule TTP_XOR_QUAD_CurrentVersionRun_f098 {
  strings:
    $key_f098 = { a3 f7 [2] 87 f9 [2] ac d5 [2] 82 f7 [2] 96 ec [2] 99 f6 [2] 87 eb [2] 85 ea [2] 9e ec [2] 82 eb [2] 9e c4 }

  condition:
    any of them
}