rule TTP_XOR_WriteProcessMemory_ee17 {
  strings:
    $key_ee17 = { b9 65 [2] 8b 47 [2] 8d 72 [2] a3 72 [2] 9c 6e }

  condition:
    any of them
}