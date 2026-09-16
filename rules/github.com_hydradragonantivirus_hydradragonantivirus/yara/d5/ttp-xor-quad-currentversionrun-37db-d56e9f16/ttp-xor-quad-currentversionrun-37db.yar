rule TTP_XOR_QUAD_CurrentVersionRun_37db {
  strings:
    $key_37db = { 64 b4 [2] 40 ba [2] 6b 96 [2] 45 b4 [2] 51 af [2] 5e b5 [2] 40 a8 [2] 42 a9 [2] 59 af [2] 45 a8 [2] 59 87 }

  condition:
    any of them
}