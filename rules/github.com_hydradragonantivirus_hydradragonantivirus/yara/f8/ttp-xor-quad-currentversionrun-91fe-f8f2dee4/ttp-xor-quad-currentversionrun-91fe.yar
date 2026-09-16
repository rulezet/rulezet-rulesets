rule TTP_XOR_QUAD_CurrentVersionRun_91fe {
  strings:
    $key_91fe = { c2 91 [2] e6 9f [2] cd b3 [2] e3 91 [2] f7 8a [2] f8 90 [2] e6 8d [2] e4 8c [2] ff 8a [2] e3 8d [2] ff a2 }

  condition:
    any of them
}