rule TTP_XOR_WriteProcessMemory_6ab6 {
  strings:
    $key_6ab6 = { 3d c4 [2] 0f e6 [2] 09 d3 [2] 27 d3 [2] 18 cf }

  condition:
    any of them
}