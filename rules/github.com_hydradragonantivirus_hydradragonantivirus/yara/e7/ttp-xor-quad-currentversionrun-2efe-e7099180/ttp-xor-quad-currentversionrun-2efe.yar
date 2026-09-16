rule TTP_XOR_QUAD_CurrentVersionRun_2efe {
  strings:
    $key_2efe = { 7d 91 [2] 59 9f [2] 72 b3 [2] 5c 91 [2] 48 8a [2] 47 90 [2] 59 8d [2] 5b 8c [2] 40 8a [2] 5c 8d [2] 40 a2 }

  condition:
    any of them
}