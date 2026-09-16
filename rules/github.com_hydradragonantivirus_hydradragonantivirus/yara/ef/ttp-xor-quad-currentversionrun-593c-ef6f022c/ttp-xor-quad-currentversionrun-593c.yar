rule TTP_XOR_QUAD_CurrentVersionRun_593c {
  strings:
    $key_593c = { 0a 53 [2] 2e 5d [2] 05 71 [2] 2b 53 [2] 3f 48 [2] 30 52 [2] 2e 4f [2] 2c 4e [2] 37 48 [2] 2b 4f [2] 37 60 }

  condition:
    any of them
}