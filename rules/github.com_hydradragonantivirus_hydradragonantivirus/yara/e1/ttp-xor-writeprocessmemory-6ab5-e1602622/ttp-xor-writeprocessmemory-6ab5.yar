rule TTP_XOR_WriteProcessMemory_6ab5 {
  strings:
    $key_6ab5 = { 3d c7 [2] 0f e5 [2] 09 d0 [2] 27 d0 [2] 18 cc }

  condition:
    any of them
}