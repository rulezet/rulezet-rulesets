rule TTP_XOR_WriteProcessMemory_70b5 {
  strings:
    $key_70b5 = { 27 c7 [2] 15 e5 [2] 13 d0 [2] 3d d0 [2] 02 cc }

  condition:
    any of them
}