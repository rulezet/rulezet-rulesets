rule TTP_XOR_WriteProcessMemory_ef34 {
  strings:
    $key_ef34 = { b8 46 [2] 8a 64 [2] 8c 51 [2] a2 51 [2] 9d 4d }

  condition:
    any of them
}