rule TTP_XOR_WriteProcessMemory_696d {
  strings:
    $key_696d = { 3e 1f [2] 0c 3d [2] 0a 08 [2] 24 08 [2] 1b 14 }

  condition:
    any of them
}