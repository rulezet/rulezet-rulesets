rule TTP_XOR_WriteProcessMemory_6ab3 {
  strings:
    $key_6ab3 = { 3d c1 [2] 0f e3 [2] 09 d6 [2] 27 d6 [2] 18 ca }

  condition:
    any of them
}