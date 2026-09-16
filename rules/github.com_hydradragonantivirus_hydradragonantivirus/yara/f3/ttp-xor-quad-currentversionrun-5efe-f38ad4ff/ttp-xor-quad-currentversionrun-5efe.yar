rule TTP_XOR_QUAD_CurrentVersionRun_5efe {
  strings:
    $key_5efe = { 0d 91 [2] 29 9f [2] 02 b3 [2] 2c 91 [2] 38 8a [2] 37 90 [2] 29 8d [2] 2b 8c [2] 30 8a [2] 2c 8d [2] 30 a2 }

  condition:
    any of them
}