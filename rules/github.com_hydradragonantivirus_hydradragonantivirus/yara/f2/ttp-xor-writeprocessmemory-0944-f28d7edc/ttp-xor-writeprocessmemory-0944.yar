rule TTP_XOR_WriteProcessMemory_0944 {
  strings:
    $key_0944 = { 5e 36 [2] 6c 14 [2] 6a 21 [2] 44 21 [2] 7b 3d }

  condition:
    any of them
}