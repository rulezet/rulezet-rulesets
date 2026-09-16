rule TTP_XOR_QUAD_CurrentVersionRun_090c {
  strings:
    $key_090c = { 5a 63 [2] 7e 6d [2] 55 41 [2] 7b 63 [2] 6f 78 [2] 60 62 [2] 7e 7f [2] 7c 7e [2] 67 78 [2] 7b 7f [2] 67 50 }

  condition:
    any of them
}