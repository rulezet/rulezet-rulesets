rule TTP_XOR_QUAD_CurrentVersionRun_090d {
  strings:
    $key_090d = { 5a 62 [2] 7e 6c [2] 55 40 [2] 7b 62 [2] 6f 79 [2] 60 63 [2] 7e 7e [2] 7c 7f [2] 67 79 [2] 7b 7e [2] 67 51 }

  condition:
    any of them
}