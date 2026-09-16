rule TTP_XOR_QUAD_CurrentVersionRun_3ffe {
  strings:
    $key_3ffe = { 6c 91 [2] 48 9f [2] 63 b3 [2] 4d 91 [2] 59 8a [2] 56 90 [2] 48 8d [2] 4a 8c [2] 51 8a [2] 4d 8d [2] 51 a2 }

  condition:
    any of them
}