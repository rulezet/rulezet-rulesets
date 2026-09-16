rule TTP_XOR_WriteProcessMemory_6a0a {
  strings:
    $key_6a0a = { 3d 78 [2] 0f 5a [2] 09 6f [2] 27 6f [2] 18 73 }

  condition:
    any of them
}