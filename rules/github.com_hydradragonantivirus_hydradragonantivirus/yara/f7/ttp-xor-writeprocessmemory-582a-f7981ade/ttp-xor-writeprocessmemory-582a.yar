rule TTP_XOR_WriteProcessMemory_582a {
  strings:
    $key_582a = { 0f 58 [2] 3d 7a [2] 3b 4f [2] 15 4f [2] 2a 53 }

  condition:
    any of them
}