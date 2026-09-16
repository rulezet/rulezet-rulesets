rule TTP_XOR_QUAD_CurrentVersionRun_111c {
  strings:
    $key_111c = { 42 73 [2] 66 7d [2] 4d 51 [2] 63 73 [2] 77 68 [2] 78 72 [2] 66 6f [2] 64 6e [2] 7f 68 [2] 63 6f [2] 7f 40 }

  condition:
    any of them
}