rule TTP_XOR_QUAD_CurrentVersionRun_300c {
  strings:
    $key_300c = { 63 63 [2] 47 6d [2] 6c 41 [2] 42 63 [2] 56 78 [2] 59 62 [2] 47 7f [2] 45 7e [2] 5e 78 [2] 42 7f [2] 5e 50 }

  condition:
    any of them
}