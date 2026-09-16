rule TTP_XOR_WriteProcessMemory_6144 {
  strings:
    $key_6144 = { 36 36 [2] 04 14 [2] 02 21 [2] 2c 21 [2] 13 3d }

  condition:
    any of them
}