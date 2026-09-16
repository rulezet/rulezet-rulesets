rule TTP_XOR_QUAD_CurrentVersionRun_373c {
  strings:
    $key_373c = { 64 53 [2] 40 5d [2] 6b 71 [2] 45 53 [2] 51 48 [2] 5e 52 [2] 40 4f [2] 42 4e [2] 59 48 [2] 45 4f [2] 59 60 }

  condition:
    any of them
}