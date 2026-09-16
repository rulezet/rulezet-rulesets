rule TTP_XOR_QUAD_CurrentVersionRun_193f {
  strings:
    $key_193f = { 4a 50 [2] 6e 5e [2] 45 72 [2] 6b 50 [2] 7f 4b [2] 70 51 [2] 6e 4c [2] 6c 4d [2] 77 4b [2] 6b 4c [2] 77 63 }

  condition:
    any of them
}