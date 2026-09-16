rule TTP_XOR_WriteProcessMemory_ee07 {
  strings:
    $key_ee07 = { b9 75 [2] 8b 57 [2] 8d 62 [2] a3 62 [2] 9c 7e }

  condition:
    any of them
}