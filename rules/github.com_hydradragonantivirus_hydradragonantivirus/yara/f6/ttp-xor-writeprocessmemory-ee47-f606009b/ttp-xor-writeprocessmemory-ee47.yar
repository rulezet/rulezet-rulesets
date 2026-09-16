rule TTP_XOR_WriteProcessMemory_ee47 {
  strings:
    $key_ee47 = { b9 35 [2] 8b 17 [2] 8d 22 [2] a3 22 [2] 9c 3e }

  condition:
    any of them
}