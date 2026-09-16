rule TTP_XOR_QUAD_CurrentVersionRun_121c {
  strings:
    $key_121c = { 41 73 [2] 65 7d [2] 4e 51 [2] 60 73 [2] 74 68 [2] 7b 72 [2] 65 6f [2] 67 6e [2] 7c 68 [2] 60 6f [2] 7c 40 }

  condition:
    any of them
}