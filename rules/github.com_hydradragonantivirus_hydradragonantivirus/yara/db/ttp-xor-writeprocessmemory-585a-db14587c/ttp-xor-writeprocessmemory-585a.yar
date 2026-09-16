rule TTP_XOR_WriteProcessMemory_585a {
  strings:
    $key_585a = { 0f 28 [2] 3d 0a [2] 3b 3f [2] 15 3f [2] 2a 23 }

  condition:
    any of them
}