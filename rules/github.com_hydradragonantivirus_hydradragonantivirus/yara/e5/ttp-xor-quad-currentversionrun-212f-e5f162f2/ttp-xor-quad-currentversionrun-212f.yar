rule TTP_XOR_QUAD_CurrentVersionRun_212f {
  strings:
    $key_212f = { 72 40 [2] 56 4e [2] 7d 62 [2] 53 40 [2] 47 5b [2] 48 41 [2] 56 5c [2] 54 5d [2] 4f 5b [2] 53 5c [2] 4f 73 }

  condition:
    any of them
}