rule TTP_XOR_WriteProcessMemory_3314 {
  strings:
    $key_3314 = { 64 66 [2] 56 44 [2] 50 71 [2] 7e 71 [2] 41 6d }

  condition:
    any of them
}