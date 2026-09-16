rule TTP_XOR_QUAD_CurrentVersionRun_eefe {
  strings:
    $key_eefe = { bd 91 [2] 99 9f [2] b2 b3 [2] 9c 91 [2] 88 8a [2] 87 90 [2] 99 8d [2] 9b 8c [2] 80 8a [2] 9c 8d [2] 80 a2 }

  condition:
    any of them
}