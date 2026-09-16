rule TTP_XOR_QUAD_CurrentVersionRun_570d {
  strings:
    $key_570d = { 04 62 [2] 20 6c [2] 0b 40 [2] 25 62 [2] 31 79 [2] 3e 63 [2] 20 7e [2] 22 7f [2] 39 79 [2] 25 7e [2] 39 51 }

  condition:
    any of them
}