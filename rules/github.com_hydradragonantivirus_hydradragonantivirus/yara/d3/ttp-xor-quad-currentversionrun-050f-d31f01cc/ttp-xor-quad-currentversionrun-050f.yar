rule TTP_XOR_QUAD_CurrentVersionRun_050f {
  strings:
    $key_050f = { 56 60 [2] 72 6e [2] 59 42 [2] 77 60 [2] 63 7b [2] 6c 61 [2] 72 7c [2] 70 7d [2] 6b 7b [2] 77 7c [2] 6b 53 }

  condition:
    any of them
}