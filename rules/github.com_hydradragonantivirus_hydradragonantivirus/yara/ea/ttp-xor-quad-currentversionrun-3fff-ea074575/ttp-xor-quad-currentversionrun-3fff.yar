rule TTP_XOR_QUAD_CurrentVersionRun_3fff {
  strings:
    $key_3fff = { 6c 90 [2] 48 9e [2] 63 b2 [2] 4d 90 [2] 59 8b [2] 56 91 [2] 48 8c [2] 4a 8d [2] 51 8b [2] 4d 8c [2] 51 a3 }

  condition:
    any of them
}