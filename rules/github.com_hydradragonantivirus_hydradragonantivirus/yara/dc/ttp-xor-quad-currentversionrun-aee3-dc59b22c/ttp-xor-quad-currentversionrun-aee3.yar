rule TTP_XOR_QUAD_CurrentVersionRun_aee3 {
  strings:
    $key_aee3 = { fd 8c [2] d9 82 [2] f2 ae [2] dc 8c [2] c8 97 [2] c7 8d [2] d9 90 [2] db 91 [2] c0 97 [2] dc 90 [2] c0 bf }

  condition:
    any of them
}