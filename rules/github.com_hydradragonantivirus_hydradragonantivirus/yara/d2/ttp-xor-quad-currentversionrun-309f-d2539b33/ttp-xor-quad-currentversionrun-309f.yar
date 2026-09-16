rule TTP_XOR_QUAD_CurrentVersionRun_309f {
  strings:
    $key_309f = { 63 f0 [2] 47 fe [2] 6c d2 [2] 42 f0 [2] 56 eb [2] 59 f1 [2] 47 ec [2] 45 ed [2] 5e eb [2] 42 ec [2] 5e c3 }

  condition:
    any of them
}