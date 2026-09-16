rule TTP_XOR_WriteProcessMemory_09b5 {
  strings:
    $key_09b5 = { 5e c7 [2] 6c e5 [2] 6a d0 [2] 44 d0 [2] 7b cc }

  condition:
    any of them
}