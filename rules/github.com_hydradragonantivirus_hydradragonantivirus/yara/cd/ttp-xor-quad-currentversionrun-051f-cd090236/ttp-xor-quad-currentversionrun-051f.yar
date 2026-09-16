rule TTP_XOR_QUAD_CurrentVersionRun_051f {
  strings:
    $key_051f = { 56 70 [2] 72 7e [2] 59 52 [2] 77 70 [2] 63 6b [2] 6c 71 [2] 72 6c [2] 70 6d [2] 6b 6b [2] 77 6c [2] 6b 43 }

  condition:
    any of them
}