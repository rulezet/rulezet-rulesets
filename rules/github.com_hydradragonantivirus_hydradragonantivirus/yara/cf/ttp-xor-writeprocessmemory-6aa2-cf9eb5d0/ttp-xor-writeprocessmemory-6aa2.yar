rule TTP_XOR_WriteProcessMemory_6aa2 {
  strings:
    $key_6aa2 = { 3d d0 [2] 0f f2 [2] 09 c7 [2] 27 c7 [2] 18 db }

  condition:
    any of them
}