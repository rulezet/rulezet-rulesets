rule TTP_XOR_WriteProcessMemory_58c6 {
  strings:
    $key_58c6 = { 0f b4 [2] 3d 96 [2] 3b a3 [2] 15 a3 [2] 2a bf }

  condition:
    any of them
}