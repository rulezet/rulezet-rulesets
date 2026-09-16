rule TTP_XOR_QUAD_CurrentVersionRun_121d {
  strings:
    $key_121d = { 41 72 [2] 65 7c [2] 4e 50 [2] 60 72 [2] 74 69 [2] 7b 73 [2] 65 6e [2] 67 6f [2] 7c 69 [2] 60 6e [2] 7c 41 }

  condition:
    any of them
}