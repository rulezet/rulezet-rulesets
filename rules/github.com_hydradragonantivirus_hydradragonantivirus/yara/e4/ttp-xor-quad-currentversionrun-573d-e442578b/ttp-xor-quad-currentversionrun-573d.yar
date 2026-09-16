rule TTP_XOR_QUAD_CurrentVersionRun_573d {
  strings:
    $key_573d = { 04 52 [2] 20 5c [2] 0b 70 [2] 25 52 [2] 31 49 [2] 3e 53 [2] 20 4e [2] 22 4f [2] 39 49 [2] 25 4e [2] 39 61 }

  condition:
    any of them
}