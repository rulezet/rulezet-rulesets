rule TTP_XOR_QUAD_CurrentVersionRun_390f {
  strings:
    $key_390f = { 6a 60 [2] 4e 6e [2] 65 42 [2] 4b 60 [2] 5f 7b [2] 50 61 [2] 4e 7c [2] 4c 7d [2] 57 7b [2] 4b 7c [2] 57 53 }

  condition:
    any of them
}